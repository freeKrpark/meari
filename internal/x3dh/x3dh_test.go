package x3dh

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"testing"
)

// bob holds everything Bob keeps on his device.
type bob struct {
	id  *Identity
	spk *SignedPreKey
	opk *OneTimePreKey
}

func newBob(t *testing.T, withOPK bool) *bob {
	t.Helper()
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	spk, err := NewSignedPreKey(id, 1)
	if err != nil {
		t.Fatal(err)
	}
	b := &bob{id: id, spk: spk}
	if withOPK {
		if b.opk, err = NewOneTimePreKey(100); err != nil {
			t.Fatal(err)
		}
	}
	return b
}

func (b *bob) bundle() *Bundle { return NewBundle(b.id, b.spk, b.opk) }

func newIdentity(t *testing.T) *Identity {
	t.Helper()
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func agree(t *testing.T, alice *Identity, b *bob) (*Result, *Result) {
	t.Helper()
	ra, msg, err := Initiate(alice, b.bundle())
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	rb, err := Respond(b.id, b.spk, b.opk, msg)
	if err != nil {
		t.Fatalf("respond: %v", err)
	}
	return ra, rb
}

func TestAgreement(t *testing.T) {
	for _, tc := range []struct {
		name    string
		withOPK bool
	}{
		{"with one-time prekey", true},
		{"without one-time prekey", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ra, rb := agree(t, newIdentity(t), newBob(t, tc.withOPK))

			if !bytes.Equal(ra.SharedKey, rb.SharedKey) {
				t.Fatal("alice and bob derived different shared keys")
			}
			if len(ra.SharedKey) != 32 {
				t.Fatalf("shared key is %d bytes, want 32", len(ra.SharedKey))
			}
			if !bytes.Equal(ra.AssociatedData, rb.AssociatedData) {
				t.Fatal("alice and bob derived different associated data")
			}
		})
	}
}

// AD must be IK_A || IK_B, initiator first.
func TestAssociatedDataOrder(t *testing.T) {
	alice, b := newIdentity(t), newBob(t, true)
	ra, _ := agree(t, alice, b)

	want := append(alice.Public().Bytes(), b.id.Public().Bytes()...)
	if !bytes.Equal(ra.AssociatedData, want) {
		t.Fatal("associated data is not IK_A || IK_B")
	}
}

// Each Initiate uses a fresh ephemeral key, so two sessions never share a key
// even against the same bundle.
func TestFreshKeyPerSession(t *testing.T) {
	alice, b := newIdentity(t), newBob(t, false)
	r1, _, err := Initiate(alice, b.bundle())
	if err != nil {
		t.Fatal(err)
	}
	r2, _, err := Initiate(alice, b.bundle())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(r1.SharedKey, r2.SharedKey) {
		t.Fatal("two sessions produced the same shared key")
	}
}

// A server that swaps in its own signed prekey cannot forge Bob's signature.
func TestRejectsSubstitutedSignedPreKey(t *testing.T) {
	alice, b := newIdentity(t), newBob(t, true)
	mallory := newBob(t, false)

	bundle := b.bundle()
	bundle.SignedPreKey = mallory.spk.Private.PublicKey()

	if _, _, err := Initiate(alice, bundle); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("want ErrInvalidSignature, got %v", err)
	}
}

func TestRejectsCorruptedSignature(t *testing.T) {
	alice, b := newIdentity(t), newBob(t, true)
	bundle := b.bundle()
	bundle.SignedPreKeySignature = bytes.Clone(bundle.SignedPreKeySignature)
	bundle.SignedPreKeySignature[0] ^= 0x01

	if _, _, err := Initiate(alice, bundle); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("want ErrInvalidSignature, got %v", err)
	}
}

// The limit of X3DH: if the server replaces Bob's whole bundle with one
// Mallory signed herself, every check passes. Only comparing identity keys
// out of band (safety numbers) can catch this. The test documents that gap.
func TestWholeBundleSubstitutionIsNotDetected(t *testing.T) {
	alice, b := newIdentity(t), newBob(t, true)
	mallory := newBob(t, true)

	ra, _, err := Initiate(alice, mallory.bundle())
	if err != nil {
		t.Fatalf("expected X3DH alone to accept Mallory's bundle, got %v", err)
	}
	if bytes.Contains(ra.AssociatedData, b.id.Public().Bytes()) {
		t.Fatal("AD unexpectedly contains Bob's identity")
	}
}

func TestRespondRejectsMismatchedPreKeys(t *testing.T) {
	alice, b := newIdentity(t), newBob(t, true)
	_, msg, err := Initiate(alice, b.bundle())
	if err != nil {
		t.Fatal(err)
	}
	otherOPK, err := NewOneTimePreKey(999)
	if err != nil {
		t.Fatal(err)
	}
	otherSPK, err := NewSignedPreKey(b.id, 2)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		spk  *SignedPreKey
		opk  *OneTimePreKey
	}{
		{"missing one-time prekey", b.spk, nil},
		{"wrong one-time prekey", b.spk, otherOPK},
		{"wrong signed prekey", otherSPK, b.opk},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Respond(b.id, tc.spk, tc.opk, msg); !errors.Is(err, ErrPreKeyMismatch) {
				t.Fatalf("want ErrPreKeyMismatch, got %v", err)
			}
		})
	}
}

// An attacker who sends a low-order ephemeral key must get an error, never a
// key whose value they can predict.
func TestRespondRejectsLowOrderEphemeral(t *testing.T) {
	alice, b := newIdentity(t), newBob(t, true)
	_, msg, err := Initiate(alice, b.bundle())
	if err != nil {
		t.Fatal(err)
	}
	zero, err := ecdh.X25519().NewPublicKey(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	msg.Ephemeral = zero

	if _, err := Respond(b.id, b.spk, b.opk, msg); err == nil {
		t.Fatal("Respond accepted a low-order ephemeral key")
	}
}
