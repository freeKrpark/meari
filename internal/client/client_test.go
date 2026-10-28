package client

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/freekrpark/meari/internal/api"
	"github.com/freekrpark/meari/internal/server"
	"github.com/freekrpark/meari/internal/vault"
)

// fast keeps tests quick. Real clients use vault.DefaultParams.
var fast = vault.Params{Time: 1, MemoryKib: 64, Threads: 1}

// relay is a test server that can record, drop or rewrite traffic.
type relay struct {
	url string

	mu      sync.Mutex
	sent    [][]byte // every message body POSTed
	dropOne bool     // drop the next message instead of delivering it
	// rewrite, if set, may replace a response for GET requests.
	rewrite func(path string) ([]byte, bool)
}

func newRelay(t *testing.T) *relay {
	t.Helper()
	r := &relay{}
	srv := server.New(server.NewMemoryStore())
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		rewrite, drop := r.rewrite, false
		if req.Method == "POST" && strings.HasPrefix(req.URL.Path, api.PathMessages) {
			body, _ := io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewReader(body))
			r.sent = append(r.sent, body)
			drop, r.dropOne = r.dropOne, false
		}
		r.mu.Unlock()

		if drop {
			w.WriteHeader(http.StatusAccepted) // pretend it was delivered
			return
		}
		if rewrite != nil && req.Method == "GET" {
			if b, ok := rewrite(req.URL.Path); ok {
				w.Write(b)
				return
			}
		}
		srv.ServeHTTP(w, req)
	}))
	t.Cleanup(ts.Close)
	r.url = ts.URL
	return r
}

type user struct {
	*Client
	path, password string
}

func newUser(t *testing.T, r *relay, name string) *user {
	t.Helper()
	u := &user{path: filepath.Join(t.TempDir(), name+".vault"), password: name + "-pw"}
	c, err := Init(u.path, r.url, []byte(u.password), fast)
	if err != nil {
		t.Fatal(err)
	}
	u.Client = c
	return u
}

// restart drops the in-memory client and reopens it from disk.
func (u *user) restart(t *testing.T) {
	t.Helper()
	c, err := Open(u.path, []byte(u.password))
	if err != nil {
		t.Fatal(err)
	}
	u.Client = c
}

func (u *user) send(t *testing.T, to *user, text string) {
	t.Helper()
	if err := u.Send(to.ID(), text); err != nil {
		t.Fatal(err)
	}
}

// expect receives and checks the exact messages, in order, from one sender.
func (u *user) expect(t *testing.T, from *user, texts ...string) {
	t.Helper()
	got, err := u.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(texts) {
		t.Fatalf("got %d messages, want %d: %+v", len(got), len(texts), got)
	}
	for i, m := range got {
		if m.Err != nil {
			t.Fatalf("message %d: %v", i, m.Err)
		}
		if m.From != from.ID() || m.Text != texts[i] {
			t.Fatalf("message %d: got %q from %s, want %q from %s", i, m.Text, m.From, texts[i], from.ID())
		}
	}
}

func TestConversation(t *testing.T) {
	r := newRelay(t)
	alice, bob := newUser(t, r, "alice"), newUser(t, r, "bob")

	alice.send(t, bob, "hi bob")
	alice.send(t, bob, "are you there?")
	bob.expect(t, alice, "hi bob", "are you there?")

	bob.send(t, alice, "hi alice")
	alice.expect(t, bob, "hi alice")

	for range 3 {
		alice.send(t, bob, "ping")
		bob.expect(t, alice, "ping")
		bob.send(t, alice, "pong")
		alice.expect(t, bob, "pong")
	}
	bob.expect(t, alice) // inbox is empty: everything was acknowledged
}

// Both sides restart between every step; the conversation must carry on.
func TestConversationSurvivesRestarts(t *testing.T) {
	r := newRelay(t)
	alice, bob := newUser(t, r, "alice"), newUser(t, r, "bob")

	for range 3 {
		alice.restart(t)
		alice.send(t, bob, "a")
		bob.restart(t)
		bob.expect(t, alice, "a")
		bob.restart(t)
		bob.send(t, alice, "b")
		alice.restart(t)
		alice.expect(t, bob, "b")
	}
}

// The one-time prekey that started a session is gone from the vault, so
// replaying Alice's first message cannot recreate the session.
func TestOneTimePreKeyDeletedAfterUse(t *testing.T) {
	r := newRelay(t)
	alice, bob := newUser(t, r, "alice"), newUser(t, r, "bob")
	before := len(bob.st.OneTimePreKeys)

	alice.send(t, bob, "hello")
	bob.expect(t, alice, "hello")
	bob.restart(t)

	if after := len(bob.st.OneTimePreKeys); after != before-1 {
		t.Fatalf("one-time prekeys: %d before, %d after; want one deleted", before, after)
	}
}

// A recorded first message, sent again later, must not decrypt a second
// time, even after Bob restarts.
func TestReplayedFirstMessageRejected(t *testing.T) {
	r := newRelay(t)
	alice, bob := newUser(t, r, "alice"), newUser(t, r, "bob")
	alice.send(t, bob, "transfer 100")
	bob.expect(t, alice, "transfer 100")
	recorded := r.sent[0]

	bob.restart(t)
	if _, err := alice.call("POST", api.PathMessages+"/"+bob.ID().String(), recorded, true, http.StatusAccepted); err != nil {
		t.Fatal(err)
	}
	got, err := bob.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Err == nil {
		t.Fatalf("replay was accepted: %+v", got)
	}
	bob.expect(t, alice) // and it was removed from the server
}

// If Alice's first message is lost, her next one still carries the X3DH
// header, so Bob can start the session from it.
func TestFirstMessageLost(t *testing.T) {
	r := newRelay(t)
	alice, bob := newUser(t, r, "alice"), newUser(t, r, "bob")

	r.mu.Lock()
	r.dropOne = true
	r.mu.Unlock()
	alice.send(t, bob, "lost")
	alice.send(t, bob, "second")

	got, err := bob.Receive()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Err != nil || got[0].Text != "second" {
		t.Fatalf("got %+v", got)
	}
	bob.send(t, alice, "got it")
	alice.expect(t, bob, "got it")
	if alice.st.Peers[bob.ID().String()].PendingInit != nil {
		t.Fatal("alice still attaches X3DH header after bob replied")
	}
}

// A server that hands out Mallory's bundle under Bob's ID is caught, because
// Bob's ID is derived from his key.
func TestServerSubstitutedBundleRejected(t *testing.T) {
	r := newRelay(t)
	alice, bob, mallory := newUser(t, r, "alice"), newUser(t, r, "bob"), newUser(t, r, "mallory")

	malloryBundle, err := alice.call("GET", api.PathBundles+"/"+mallory.ID().String(), nil, true, http.StatusOK)
	if err != nil {
		t.Fatal(err)
	}
	r.mu.Lock()
	r.rewrite = func(path string) ([]byte, bool) {
		return malloryBundle, path == api.PathBundles+"/"+bob.ID().String()
	}
	r.mu.Unlock()

	if err := alice.Send(bob.ID(), "for bob only"); !errors.Is(err, ErrWrongIdentity) {
		t.Fatalf("want ErrWrongIdentity, got %v", err)
	}
	if len(r.sent) != 0 {
		t.Fatal("a message was sent despite the substituted bundle")
	}
}

func TestOpenWrongPassword(t *testing.T) {
	r := newRelay(t)
	alice := newUser(t, r, "alice")
	if _, err := Open(alice.path, []byte("wrong")); !errors.Is(err, vault.ErrDecrypt) {
		t.Fatalf("want vault.ErrDecrypt, got %v", err)
	}
}

func TestInitRefusesToOverwrite(t *testing.T) {
	r := newRelay(t)
	alice := newUser(t, r, "alice")
	before, _ := os.ReadFile(alice.path)

	if _, err := Init(alice.path, r.url, []byte("other"), fast); !errors.Is(err, ErrExists) {
		t.Fatalf("want ErrExists, got %v", err)
	}
	after, _ := os.ReadFile(alice.path)
	if !bytes.Equal(before, after) {
		t.Fatal("existing vault was modified")
	}
}

// Neither the vault file nor the server ever holds the message text.
func TestNoPlaintextAtRest(t *testing.T) {
	r := newRelay(t)
	alice, bob := newUser(t, r, "alice"), newUser(t, r, "bob")
	const secret = "the password is swordfish"

	alice.send(t, bob, secret)
	for _, body := range r.sent {
		if bytes.Contains(body, []byte(secret)) {
			t.Fatal("plaintext sent to the server")
		}
	}
	bob.expect(t, alice, secret)

	for _, u := range []*user{alice, bob} {
		file, err := os.ReadFile(u.path)
		if err != nil {
			t.Fatal(err)
		}
		for _, leak := range [][]byte{[]byte(secret), u.st.Identity} {
			if bytes.Contains(file, leak) {
				t.Fatalf("%s's vault file contains secret material", u.path)
			}
		}
	}
}

func TestMessageTooLarge(t *testing.T) {
	r := newRelay(t)
	alice, bob := newUser(t, r, "alice"), newUser(t, r, "bob")
	if err := alice.Send(bob.ID(), strings.Repeat("x", MaxPlaintext+1)); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("want ErrMessageTooLarge, got %v", err)
	}
}
