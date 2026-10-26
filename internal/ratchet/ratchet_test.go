package ratchet

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/freekrpark/meari/internal/x3dh"
)

func newPair(t *testing.T) (alice, bob *Session) {
	t.Helper()
	aliceID, err := x3dh.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bobID, err := x3dh.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	spk, err := x3dh.NewSignedPreKey(bobID, 1)
	if err != nil {
		t.Fatal(err)
	}
	bundle := x3dh.NewBundle(bobID, spk, nil)

	ra, msg, err := x3dh.Initiate(aliceID, bundle)
	if err != nil {
		t.Fatal(err)
	}
	rb, err := x3dh.Respond(bobID, spk, nil, msg)
	if err != nil {
		t.Fatal(err)
	}

	alice, err = NewInitiator(ra.SharedKey, ra.AssociatedData, bundle.SignedPreKey)
	if err != nil {
		t.Fatal(err)
	}
	bob = NewResponder(rb.SharedKey, rb.AssociatedData, spk.Private)
	return alice, bob
}

func send(t *testing.T, s *Session, text string) *Message {
	t.Helper()
	m, err := s.Encrypt([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func receive(t *testing.T, s *Session, m *Message, want string) {
	t.Helper()
	pt, err := s.Decrypt(m)
	if err != nil {
		t.Fatalf("decrypt %q: %v", want, err)
	}
	if string(pt) != want {
		t.Fatalf("got %q, want %q", pt, want)
	}
}

func TestConversation(t *testing.T) {
	alice, bob := newPair(t)
	for round := range 5 {
		for i := range 3 {
			text := fmt.Sprintf("alice %d-%d", round, i)
			receive(t, bob, send(t, alice, text), text)
		}
		for i := range 2 {
			text := fmt.Sprintf("bob %d-%d", round, i)
			receive(t, alice, send(t, bob, text), text)
		}
	}
}

func TestResponderCannotSendFirst(t *testing.T) {
	_, bob := newPair(t)
	if _, err := bob.Encrypt([]byte("hi")); !errors.Is(err, ErrCannotSendYet) {
		t.Fatalf("want ErrCannotSendYet, got %v", err)
	}
}

func TestOutOfOrderSameChain(t *testing.T) {
	alice, bob := newPair(t)
	m0, m1, m2 := send(t, alice, "0"), send(t, alice, "1"), send(t, alice, "2")

	receive(t, bob, m2, "2")
	receive(t, bob, m0, "0")
	receive(t, bob, m1, "1")
}

func TestOutOfOrderAcrossRatchet(t *testing.T) {
	alice, bob := newPair(t)
	a0, a1 := send(t, alice, "a0"), send(t, alice, "a1")
	receive(t, bob, a0, "a0")

	receive(t, alice, send(t, bob, "b0"), "b0")
	a2 := send(t, alice, "a2")

	receive(t, bob, a2, "a2")
	receive(t, bob, a1, "a1")
}

func TestReplayRejected(t *testing.T) {
	alice, bob := newPair(t)
	m := send(t, alice, "once")
	receive(t, bob, m, "once")

	if _, err := bob.Decrypt(m); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("replayed message: want ErrDecrypt, got %v", err)
	}
}

func TestReplayOfSkippedKeyRejected(t *testing.T) {
	alice, bob := newPair(t)
	m0, m1 := send(t, alice, "0"), send(t, alice, "1")
	receive(t, bob, m1, "1")
	receive(t, bob, m0, "0")

	if _, err := bob.Decrypt(m0); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("replayed skipped message: want ErrDecrypt, got %v", err)
	}
}

func TestTamperingLeavesStateUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name   string
		tamper func(*Message)
	}{
		{"ciphertext", func(m *Message) { m.Ciphertext[0] ^= 0x01 }},
		{"header N", func(m *Message) { m.Header.N += 5 }},
		{"header PN", func(m *Message) { m.Header.PN++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			alice, bob := newPair(t)
			m := send(t, alice, "real")

			forged := &Message{Header: m.Header, Ciphertext: bytes.Clone(m.Ciphertext)}
			tc.tamper(forged)
			if _, err := bob.Decrypt(forged); err == nil {
				t.Fatal("forged message decrypted")
			}
			receive(t, bob, m, "real")
		})
	}
}

func TestTooManySkipped(t *testing.T) {
	alice, bob := newPair(t)
	receive(t, bob, send(t, alice, "first"), "first")

	m := send(t, alice, "far ahead")
	m.Header.N = MaxSkip + 10
	if _, err := bob.Decrypt(m); !errors.Is(err, ErrTooManySkipped) {
		t.Fatalf("want ErrTooManySkipped, got %v", err)
	}
}

func TestRatchetKeyRotatesEachTurn(t *testing.T) {
	alice, bob := newPair(t)
	a0 := send(t, alice, "a0")
	receive(t, bob, a0, "a0")
	receive(t, alice, send(t, bob, "b0"), "b0")
	a1 := send(t, alice, "a1")

	if a0.Header.DH.Equal(a1.Header.DH) {
		t.Fatal("alice's ratchet key did not change after bob replied")
	}
}

func TestSamePlaintextDifferentCiphertext(t *testing.T) {
	alice, _ := newPair(t)
	m1, m2 := send(t, alice, "same"), send(t, alice, "same")
	if bytes.Equal(m1.Ciphertext, m2.Ciphertext) {
		t.Fatal("two messages with the same plaintext share a ciphertext")
	}
}

func TestWrongAssociatedData(t *testing.T) {
	alice, bob := newPair(t)
	bob.ad = bytes.Clone(bob.ad)
	bob.ad[0] ^= 0x01

	if _, err := bob.Decrypt(send(t, alice, "hi")); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
}
