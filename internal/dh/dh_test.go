package dh

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"testing"
)

func mustKeyPair(t *testing.T) *KeyPair {
	t.Helper()
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func mustDH(t *testing.T, priv *ecdh.PrivateKey, pub *ecdh.PublicKey) []byte {
	t.Helper()
	s, err := DH(priv, pub)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSharedSecretMatches(t *testing.T) {
	alice, bob := mustKeyPair(t), mustKeyPair(t)

	s1 := mustDH(t, alice.Private, bob.Public)
	s2 := mustDH(t, bob.Private, alice.Public)

	if !bytes.Equal(s1, s2) {
		t.Fatal("alice and bob derived different shared secrets")
	}
	if len(s1) != SecretSize {
		t.Fatalf("want %d bytes, got %d", SecretSize, len(s1))
	}
}

func TestEveGetsDifferentSecret(t *testing.T) {
	alice, bob, eve := mustKeyPair(t), mustKeyPair(t), mustKeyPair(t)

	aliceBob := mustDH(t, alice.Private, bob.Public)
	eveBob := mustDH(t, eve.Private, bob.Public)
	eveAlice := mustDH(t, eve.Private, alice.Public)

	if bytes.Equal(aliceBob, eveBob) || bytes.Equal(aliceBob, eveAlice) {
		t.Fatal("eve derived the alice-bob shared secret")
	}
}

func TestKeyPairsAreUnique(t *testing.T) {
	a, b := mustKeyPair(t), mustKeyPair(t)
	if bytes.Equal(a.Public.Bytes(), b.Public.Bytes()) {
		t.Fatal("two generated key pairs are identical; randomness is broken")
	}
}

// An all-zero public key is a low-order point on Curve25519. Multiplying it by
// any private key gives an all-zero result, so an attacker who substitutes it
// can force a "shared secret" they already know. RFC 7748 section 6.1 says to
// check for this; crypto/ecdh does, and DH must surface the error.
func TestAllZeroPublicKeyRejected(t *testing.T) {
	alice := mustKeyPair(t)

	zero, err := ecdh.X25519().NewPublicKey(make([]byte, 32))
	if err != nil {
		t.Fatalf("constructing zero key: %v", err)
	}

	secret, err := DH(alice.Private, zero)
	if err == nil {
		t.Fatalf("DH accepted a low-order public key, secret=%x", secret)
	}
	t.Logf("rejected as expected: %v", err)
}

// RFC 7748 section 6.1 test vector: fixed keys must give a fixed secret.
// Random-key tests only prove both sides agree; this proves we agree with
// every other correct X25519 implementation.
func TestRFC7748Vector(t *testing.T) {
	curve := ecdh.X25519()
	alicePriv, err := curve.NewPrivateKey(unhex(t,
		"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
	if err != nil {
		t.Fatal(err)
	}
	bobPriv, err := curve.NewPrivateKey(unhex(t,
		"5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
	if err != nil {
		t.Fatal(err)
	}

	const (
		wantAlicePub = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
		wantBobPub   = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
		wantShared   = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
	)

	if got := hex.EncodeToString(alicePriv.PublicKey().Bytes()); got != wantAlicePub {
		t.Fatalf("alice public key\n got %s\nwant %s", got, wantAlicePub)
	}
	if got := hex.EncodeToString(bobPriv.PublicKey().Bytes()); got != wantBobPub {
		t.Fatalf("bob public key\n got %s\nwant %s", got, wantBobPub)
	}

	for _, tc := range []struct {
		name string
		priv *ecdh.PrivateKey
		pub  *ecdh.PublicKey
	}{
		{"alice side", alicePriv, bobPriv.PublicKey()},
		{"bob side", bobPriv, alicePriv.PublicKey()},
	} {
		if got := hex.EncodeToString(mustDH(t, tc.priv, tc.pub)); got != wantShared {
			t.Fatalf("%s shared secret\n got %s\nwant %s", tc.name, got, wantShared)
		}
	}
}
