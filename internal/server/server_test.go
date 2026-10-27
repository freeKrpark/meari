package server

import (
	"bytes"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/freekrpark/meari/internal/api"
	"github.com/freekrpark/meari/internal/auth"
	"github.com/freekrpark/meari/internal/ratchet"
	"github.com/freekrpark/meari/internal/wire"
	"github.com/freekrpark/meari/internal/x3dh"
)

// client is a minimal test client: an identity plus signed HTTP calls.
type client struct {
	t      *testing.T
	base   string
	id     *x3dh.Identity
	lastTS int64
}

func newClient(t *testing.T, base string) *client {
	t.Helper()
	id, err := x3dh.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return &client{t: t, base: base, id: id}
}

func (c *client) accountID() auth.AccountID { return auth.IDFor(c.id.Public()) }

// do sends a request, signed unless sign is false, and returns status and body.
func (c *client) do(method, path string, body []byte, sign bool) (int, []byte) {
	c.t.Helper()
	req, err := http.NewRequest(method, c.base+path, bytes.NewReader(body))
	if err != nil {
		c.t.Fatal(err)
	}
	if sign {
		ts := max(time.Now().UnixNano(), c.lastTS+1)
		c.lastTS = ts
		if err := auth.Sign(req, c.id, body, ts); err != nil {
			c.t.Fatal(err)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		c.t.Fatal(err)
	}
	return resp.StatusCode, out
}

func (c *client) mustDo(want int, method, path string, body []byte) []byte {
	c.t.Helper()
	code, out := c.do(method, path, body, true)
	if code != want {
		c.t.Fatalf("%s %s: status %d, want %d (%s)", method, path, code, want, out)
	}
	return out
}

func (c *client) register() {
	c.t.Helper()
	code, out := c.do("PUT", api.PathAccounts, c.id.Public().Bytes(), false)
	if code != http.StatusOK || string(out) != c.accountID().String() {
		c.t.Fatalf("register: %d %q", code, out)
	}
}

func (c *client) inbox() []api.Delivery {
	c.t.Helper()
	items, err := api.DecodeList(c.mustDo(200, "GET", api.PathInbox, nil), MaxInbox, MaxEnvelope+64)
	if err != nil {
		c.t.Fatal(err)
	}
	out := make([]api.Delivery, len(items))
	for i, it := range items {
		if err := out[i].UnmarshalBinary(it); err != nil {
			c.t.Fatal(err)
		}
	}
	return out
}

// bob's private prekeys, kept on his device.
type prekeys struct {
	spk *x3dh.SignedPreKey
	opk map[uint32]*x3dh.OneTimePreKey
}

// uploadBundles publishes a fallback bundle plus n one-time bundles.
func (c *client) uploadBundles(n int) *prekeys {
	c.t.Helper()
	spk, err := x3dh.NewSignedPreKey(c.id, 1)
	if err != nil {
		c.t.Fatal(err)
	}
	keys := &prekeys{spk: spk, opk: map[uint32]*x3dh.OneTimePreKey{}}
	items := [][]byte{wire.MarshalBundle(x3dh.NewBundle(c.id, spk, nil))}
	for i := range n {
		opk, err := x3dh.NewOneTimePreKey(uint32(100 + i))
		if err != nil {
			c.t.Fatal(err)
		}
		keys.opk[opk.ID] = opk
		items = append(items, wire.MarshalBundle(x3dh.NewBundle(c.id, spk, opk)))
	}
	c.mustDo(http.StatusNoContent, "PUT", api.PathBundles, api.EncodeList(items))
	return keys
}

func newTestServer(t *testing.T) (*Server, *MemoryStore, string) {
	t.Helper()
	store := NewMemoryStore()
	srv := New(store)
	ts := httptest.NewServer(srv)
	t.Cleanup(ts.Close)
	return srv, store, ts.URL
}

// The stage 1 goal: two clients talk through the server, and the server's
// storage never contains the plaintext.
func TestEndToEnd(t *testing.T) {
	_, store, url := newTestServer(t)
	alice, bob := newClient(t, url), newClient(t, url)
	alice.register()
	bob.register()
	bobKeys := bob.uploadBundles(5)
	const secret = "meet at the usual place"

	// Alice knows Bob's ID out of band and fetches his bundle.
	bobID := bob.accountID()
	bundle, err := wire.UnmarshalBundle(alice.mustDo(200, "GET", api.PathBundles+"/"+bobID.String(), nil))
	if err != nil {
		t.Fatal(err)
	}
	if !bobID.Matches(bundle.Identity) {
		t.Fatal("server returned a bundle for someone else")
	}

	ra, init, err := x3dh.Initiate(alice.id, bundle)
	if err != nil {
		t.Fatal(err)
	}
	aliceSess, err := ratchet.NewInitiator(ra.SharedKey, ra.AssociatedData, bundle.SignedPreKey)
	if err != nil {
		t.Fatal(err)
	}
	m, err := aliceSess.Encrypt([]byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	env, _ := (&wire.Envelope{Init: init, Message: m}).MarshalBinary()
	alice.mustDo(http.StatusAccepted, "POST", api.PathMessages+"/"+bobID.String(), env)

	// What would someone who seized the server see right now?
	assertNoPlaintext(t, store, secret)

	// Bob picks it up.
	in := bob.inbox()
	if len(in) != 1 || in[0].From != alice.accountID() {
		t.Fatalf("bob's inbox: %+v", in)
	}
	var got wire.Envelope
	if err := got.UnmarshalBinary(in[0].Data); err != nil {
		t.Fatal(err)
	}
	if !in[0].From.Matches(got.Init.Identity) {
		t.Fatal("initial message identity does not match the sender's account")
	}
	opk := bobKeys.opk[got.Init.OneTimePreKeyID]
	rb, err := x3dh.Respond(bob.id, bobKeys.spk, opk, got.Init)
	if err != nil {
		t.Fatal(err)
	}
	delete(bobKeys.opk, got.Init.OneTimePreKeyID)
	bobSess := ratchet.NewResponder(rb.SharedKey, rb.AssociatedData, bobKeys.spk.Private)
	pt, err := bobSess.Decrypt(got.Message)
	if err != nil || string(pt) != secret {
		t.Fatalf("bob decrypted %q, %v", pt, err)
	}

	// Ack deletes it from the server.
	bob.mustDo(http.StatusNoContent, "DELETE", api.PathInbox+"/"+hex.EncodeToString(in[0].ID[:]), nil)
	if left := bob.inbox(); len(left) != 0 {
		t.Fatalf("message still on server after ack: %d left", len(left))
	}
}

// assertNoPlaintext scans everything the store holds.
func assertNoPlaintext(t *testing.T, s *MemoryStore, secret string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	var dump []byte
	for _, in := range s.inbox {
		for _, d := range in {
			dump = append(dump, d.Data...)
		}
	}
	for _, b := range s.fallback {
		dump = append(dump, b...)
	}
	for _, ot := range s.oneTime {
		for _, b := range ot {
			dump = append(dump, b...)
		}
	}
	if len(dump) == 0 {
		t.Fatal("store dump is empty; the check would prove nothing")
	}
	if bytes.Contains(dump, []byte(secret)) {
		t.Fatal("plaintext found in server storage")
	}
}

// One-time bundles are handed out once each; then the fallback, repeatedly.
func TestBundlesAreTakenOnce(t *testing.T) {
	_, _, url := newTestServer(t)
	alice, bob := newClient(t, url), newClient(t, url)
	alice.register()
	bob.register()
	bob.uploadBundles(2)
	path := api.PathBundles + "/" + bob.accountID().String()

	seen := map[uint32]bool{}
	for i := range 4 {
		b, err := wire.UnmarshalBundle(alice.mustDo(200, "GET", path, nil))
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case i < 2 && !b.HasOneTimePreKey:
			t.Fatalf("fetch %d: got fallback while one-time bundles remain", i)
		case i < 2 && seen[b.OneTimePreKeyID]:
			t.Fatalf("fetch %d: one-time prekey %d handed out twice", i, b.OneTimePreKeyID)
		case i >= 2 && b.HasOneTimePreKey:
			t.Fatalf("fetch %d: one-time bundle after they ran out", i)
		}
		seen[b.OneTimePreKeyID] = true
	}
}

func TestRegisterIsIdempotentAndValidates(t *testing.T) {
	_, _, url := newTestServer(t)
	c := newClient(t, url)
	c.register()
	c.register()

	for name, body := range map[string][]byte{
		"empty": nil,
		"short": c.id.Public().Bytes()[:63],
		"long":  append(c.id.Public().Bytes(), 0),
	} {
		if code, _ := c.do("PUT", api.PathAccounts, body, false); code == http.StatusOK {
			t.Errorf("%s identity accepted", name)
		}
	}
}

func TestRequiresSignature(t *testing.T) {
	_, _, url := newTestServer(t)
	c := newClient(t, url)
	c.register()
	for _, tc := range []struct{ method, path string }{
		{"PUT", api.PathBundles},
		{"GET", api.PathBundles + "/" + c.accountID().String()},
		{"POST", api.PathMessages + "/" + c.accountID().String()},
		{"GET", api.PathInbox},
		{"DELETE", api.PathInbox + "/" + hex.EncodeToString(make([]byte, 16))},
	} {
		if code, _ := c.do(tc.method, tc.path, nil, false); code != http.StatusUnauthorized {
			t.Errorf("%s %s without signature: status %d", tc.method, tc.path, code)
		}
	}
}

// Mallory can neither read nor delete Bob's messages.
func TestInboxIsPrivate(t *testing.T) {
	_, _, url := newTestServer(t)
	alice, bob, mallory := newClient(t, url), newClient(t, url), newClient(t, url)
	for _, c := range []*client{alice, bob, mallory} {
		c.register()
	}
	alice.mustDo(http.StatusAccepted, "POST", api.PathMessages+"/"+bob.accountID().String(), []byte("opaque"))
	mid := bob.inbox()[0].ID

	if in := mallory.inbox(); len(in) != 0 {
		t.Fatal("mallory sees bob's messages")
	}
	mallory.mustDo(http.StatusNotFound, "DELETE", api.PathInbox+"/"+hex.EncodeToString(mid[:]), nil)
	if len(bob.inbox()) != 1 {
		t.Fatal("mallory deleted bob's message")
	}
}

func TestSendToUnknownAccount(t *testing.T) {
	_, _, url := newTestServer(t)
	alice, stranger := newClient(t, url), newClient(t, url)
	alice.register()
	alice.mustDo(http.StatusNotFound, "POST", api.PathMessages+"/"+stranger.accountID().String(), []byte("x"))
}

func TestLimits(t *testing.T) {
	srv, _, url := newTestServer(t)
	srv.MaxInbox = 2
	alice, bob := newClient(t, url), newClient(t, url)
	alice.register()
	bob.register()
	to := api.PathMessages + "/" + bob.accountID().String()

	alice.mustDo(http.StatusRequestEntityTooLarge, "POST", to, make([]byte, MaxEnvelope+1))

	alice.mustDo(http.StatusAccepted, "POST", to, []byte("1"))
	alice.mustDo(http.StatusAccepted, "POST", to, []byte("2"))
	alice.mustDo(http.StatusTooManyRequests, "POST", to, []byte("3"))
}
