package auth

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/freekrpark/meari/internal/x3dh"
)

func newIdentity(t *testing.T) *x3dh.Identity {
	t.Helper()
	id, err := x3dh.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestIDDeterministicAndDistinct(t *testing.T) {
	a, b := newIdentity(t), newIdentity(t)
	if IDFor(a.Public()) != IDFor(a.Public()) {
		t.Fatal("same identity gave different IDs")
	}
	if IDFor(a.Public()) == IDFor(b.Public()) {
		t.Fatal("different identities gave the same ID")
	}
}

func TestIDStringRoundTrip(t *testing.T) {
	id := IDFor(newIdentity(t).Public())
	s := id.String()
	if len(s) != 32 || strings.ToLower(s) != s {
		t.Fatalf("want 32 lowercase chars, got %q", s)
	}
	got, err := ParseAccountID(s)
	if err != nil || got != id {
		t.Fatalf("round trip failed: %v", err)
	}
}

func TestParseRejectsNonCanonical(t *testing.T) {
	s := IDFor(newIdentity(t).Public()).String()
	for name, bad := range map[string]string{
		"empty":     "",
		"short":     s[:31],
		"long":      s + "a",
		"uppercase": strings.ToUpper(s),
		"newline":   s[:16] + "\n" + s[16:],
		"padding":   s + "========",
		"bad char":  s[:31] + "1",
	} {
		if _, err := ParseAccountID(bad); !errors.Is(err, ErrInvalidID) {
			t.Errorf("%s: want ErrInvalidID, got %v", name, err)
		}
	}
}

func TestIDCatchesSubstitutedIdentity(t *testing.T) {
	bob, mallory := newIdentity(t), newIdentity(t)
	bobID := IDFor(bob.Public())

	if !bobID.Matches(bob.Public()) {
		t.Fatal("bob's own identity does not match his ID")
	}
	if bobID.Matches(mallory.Public()) {
		t.Fatal("mallory's identity matched bob's ID")
	}
}

type server struct {
	now time.Time
	v   *Verifier
}

func newServer(ids ...*x3dh.Identity) *server {
	known := map[AccountID]x3dh.PublicIdentity{}
	for _, id := range ids {
		known[IDFor(id.Public())] = id.Public()
	}
	s := &server{now: time.Unix(1_800_000_000, 0)}
	s.v = &Verifier{
		Lookup: func(a AccountID) (x3dh.PublicIdentity, bool) { p, ok := known[a]; return p, ok },
		Now:    func() time.Time { return s.now },
	}
	return s
}

func signed(t *testing.T, id *x3dh.Identity, method, target string, body []byte, ts time.Time) *http.Request {
	t.Helper()
	r := httptest.NewRequest(method, target, bytes.NewReader(body))
	if err := Sign(r, id, body, ts.UnixNano()); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestVerifyAccepts(t *testing.T) {
	alice := newIdentity(t)
	s := newServer(alice)
	body := []byte("payload")

	got, err := s.v.Verify(signed(t, alice, "POST", "/v1/messages?x=1", body, s.now), body)
	if err != nil {
		t.Fatal(err)
	}
	if got != IDFor(alice.Public()) {
		t.Fatal("verified as the wrong account")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	alice := newIdentity(t)
	body := []byte("payload")

	for _, tc := range []struct {
		name   string
		mutate func(r *http.Request) []byte
	}{
		{"body", func(r *http.Request) []byte { return []byte("payloaD") }},
		{"method", func(r *http.Request) []byte { r.Method = "DELETE"; return body }},
		{"path", func(r *http.Request) []byte { r.RequestURI = "/v1/other"; return body }},
		{"query", func(r *http.Request) []byte { r.RequestURI = "/v1/messages?x=2"; return body }},
		{"timestamp", func(r *http.Request) []byte {
			r.Header.Set(HeaderTimestamp, "1800000000000000001")
			return body
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newServer(alice)
			r := signed(t, alice, "POST", "/v1/messages?x=1", body, s.now)
			sent := tc.mutate(r)
			if _, err := s.v.Verify(r, sent); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("want ErrBadSignature, got %v", err)
			}
		})
	}
}

// Mallory signs with her own key but claims to be Alice.
func TestVerifyRejectsImpersonation(t *testing.T) {
	alice, mallory := newIdentity(t), newIdentity(t)
	s := newServer(alice, mallory)

	r := signed(t, mallory, "GET", "/v1/messages", nil, s.now)
	r.Header.Set(HeaderAccount, IDFor(alice.Public()).String())

	if _, err := s.v.Verify(r, nil); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestVerifyRejectsUnknownAccount(t *testing.T) {
	s := newServer()
	stranger := newIdentity(t)
	if _, err := s.v.Verify(signed(t, stranger, "GET", "/", nil, s.now), nil); !errors.Is(err, ErrUnknownAcct) {
		t.Fatalf("want ErrUnknownAcct, got %v", err)
	}
}

func TestVerifyRejectsStale(t *testing.T) {
	alice := newIdentity(t)
	for name, off := range map[string]time.Duration{
		"too old":   -DefaultMaxSkew - time.Second,
		"in future": DefaultMaxSkew + time.Second,
	} {
		s := newServer(alice)
		r := signed(t, alice, "GET", "/", nil, s.now.Add(off))
		if _, err := s.v.Verify(r, nil); !errors.Is(err, ErrStale) {
			t.Errorf("%s: want ErrStale, got %v", name, err)
		}
	}
}

func TestVerifyRejectsReplay(t *testing.T) {
	alice := newIdentity(t)
	s := newServer(alice)

	r1 := signed(t, alice, "PUT", "/v1/prekeys", []byte("old keys"), s.now)
	if _, err := s.v.Verify(r1, []byte("old keys")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.v.Verify(r1, []byte("old keys")); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay: want ErrReplay, got %v", err)
	}

	older := signed(t, alice, "GET", "/", nil, s.now.Add(-time.Second))
	if _, err := s.v.Verify(older, nil); !errors.Is(err, ErrReplay) {
		t.Fatalf("older timestamp: want ErrReplay, got %v", err)
	}

	newer := signed(t, alice, "GET", "/", nil, s.now.Add(time.Nanosecond))
	if _, err := s.v.Verify(newer, nil); err != nil {
		t.Fatalf("newer request rejected: %v", err)
	}
}

func TestForgedRequestDoesNotAdvanceReplayClock(t *testing.T) {
	alice, mallory := newIdentity(t), newIdentity(t)
	s := newServer(alice)

	forged := signed(t, mallory, "GET", "/", nil, s.now.Add(time.Minute))
	forged.Header.Set(HeaderAccount, IDFor(alice.Public()).String())
	if _, err := s.v.Verify(forged, nil); err == nil {
		t.Fatal("forged request accepted")
	}

	if _, err := s.v.Verify(signed(t, alice, "GET", "/", nil, s.now), nil); err != nil {
		t.Fatalf("alice locked out after forged request: %v", err)
	}
}

func TestVerifyRejectsMalformedHeaders(t *testing.T) {
	alice := newIdentity(t)
	for _, tc := range []struct {
		name, header, value string
		want                error
	}{
		{"no account", HeaderAccount, "", ErrMissingAuth},
		{"bad account", HeaderAccount, "nope", ErrBadAuthHeader},
		{"bad timestamp", HeaderTimestamp, "soon", ErrBadAuthHeader},
		{"bad signature", HeaderSignature, "!!!", ErrBadAuthHeader},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newServer(alice)
			r := signed(t, alice, "GET", "/", nil, s.now)
			r.Header.Set(tc.header, tc.value)
			if _, err := s.v.Verify(r, nil); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}
