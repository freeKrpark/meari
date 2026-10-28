package ratchet

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func saveLoad(t *testing.T, s *Session) *Session {
	t.Helper()
	b, err := json.Marshal(s.State())
	if err != nil {
		t.Fatal(err)
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatal(err)
	}
	r, err := Restore(st)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestConversationSurvivesRestarts(t *testing.T) {
	alice, bob := newPair(t)
	bob = saveLoad(t, bob) // responder that has not received anything yet

	for round := range 3 {
		alice = saveLoad(t, alice)
		receive(t, bob, send(t, alice, "a"), "a")
		bob = saveLoad(t, bob)
		receive(t, alice, send(t, bob, "b"), "b")
		if round == 1 {
			alice, bob = saveLoad(t, alice), saveLoad(t, bob)
		}
	}
}
func TestSkippedKeysSurviveRestart(t *testing.T) {
	alice, bob := newPair(t)
	m0, m1, m2 := send(t, alice, "0"), send(t, alice, "1"), send(t, alice, "2")
	receive(t, bob, m2, "2") // stores keys for 0 and 1

	if got := len(bob.State().Skipped); got != 2 {
		t.Fatalf("want 2 skipped keys, got %d", got)
	}
	bob = saveLoad(t, bob)
	receive(t, bob, m0, "0")
	receive(t, bob, m1, "1")
}

func TestSnapshotIsIndependent(t *testing.T) {
	alice, bob := newPair(t)
	st := alice.State()
	for i := range st.RK {
		st.RK[i] = 0
	}
	for i := range st.CKs {
		st.CKs[i] = 0
	}
	receive(t, bob, send(t, alice, "still works"), "still works")
}

func TestSnapshotIsDeterministic(t *testing.T) {
	alice, bob := newPair(t)
	var last *Message
	for range 10 {
		last = send(t, alice, "x")
	}
	receive(t, bob, last, "x")

	a, _ := json.Marshal(bob.State())
	for range 5 {
		b, _ := json.Marshal(bob.State())
		if !bytes.Equal(a, b) {
			t.Fatal("snapshot changed between calls")
		}
	}
}

func TestRestoreRejectsBadState(t *testing.T) {
	alice, bob := newPair(t)
	send(t, alice, "0") // never delivered, so Bob stores its key
	receive(t, bob, send(t, alice, "1"), "1")
	good := bob.State()
	if len(good.Skipped) != 1 {
		t.Fatalf("test setup: want 1 skipped key, got %d", len(good.Skipped))
	}

	for name, mutate := range map[string]func(*State){
		"short private key": func(s *State) { s.DHs = s.DHs[:31] },
		"short root key":    func(s *State) { s.RK = s.RK[:31] },
		"short chain key":   func(s *State) { s.CKr = s.CKr[:31] },
		"missing AD":        func(s *State) { s.AD = nil },
		"chain without key": func(s *State) { s.DHr = nil },
		"short skipped DH":  func(s *State) { s.Skipped[0].DH = s.Skipped[0].DH[:31] },
		"short skipped MK":  func(s *State) { s.Skipped[0].MK = nil },
		"duplicate skipped": func(s *State) { s.Skipped = append(s.Skipped, s.Skipped[0]) },
		"too many skipped": func(s *State) {
			s.Skipped = make([]SkippedKey, maxStoredSkipped+1)
		},
	} {
		st := bob.State()
		mutate(&st)
		if _, err := Restore(st); !errors.Is(err, ErrBadState) {
			t.Errorf("%s: want ErrBadState, got %v", name, err)
		}
	}
}

func TestStaleStateReusesMessageKey(t *testing.T) {
	alice, _ := newPair(t)
	stale := alice.State()
	first := send(t, alice, "attack at dawn")

	restored, err := Restore(stale)
	if err != nil {
		t.Fatal(err)
	}
	second := send(t, restored, "attack at dusk")

	if first.Header.N != second.Header.N {
		t.Fatal("expected the stale session to reuse the message number")
	}
	// Same key and nonce: XOR of ciphertexts equals XOR of plaintexts.
	p1, p2 := []byte("attack at dawn"), []byte("attack at dusk")
	for i := range p1 {
		if first.Ciphertext[i]^second.Ciphertext[i] != p1[i]^p2[i] {
			t.Fatal("expected keystream reuse")
		}
	}
}
