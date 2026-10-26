package x3dh

import (
	"crypto/ed25519"
	"errors"
	"testing"
)

func TestSignWithContext(t *testing.T) {
	id := newIdentity(t)
	msg := []byte("hello")

	sig, err := id.SignWithContext("ctx A", msg)
	if err != nil {
		t.Fatal(err)
	}
	pub := id.Public()

	if !pub.VerifyWithContext("ctx A", msg, sig) {
		t.Fatal("valid signature rejected")
	}
	if pub.VerifyWithContext("ctx B", msg, sig) {
		t.Fatal("signature verified under a different context")
	}
	if pub.VerifyWithContext("ctx A", []byte("hellO"), sig) {
		t.Fatal("signature verified for a different message")
	}
	if pub.VerifyWithContext("ctx A", msg, sig[:len(sig)-1]) {
		t.Fatal("truncated signature verified")
	}
	if newIdentity(t).Public().VerifyWithContext("ctx A", msg, sig) {
		t.Fatal("signature verified under another identity")
	}
}
func TestContextSignaturesAreSeparateFromPrekeySignatures(t *testing.T) {
	id := newIdentity(t)
	spk, err := NewSignedPreKey(id, 1)
	if err != nil {
		t.Fatal(err)
	}
	pub := id.Public()
	spkBytes := spk.Private.PublicKey().Bytes()

	if pub.VerifyWithContext("any", spkBytes, spk.Signature) {
		t.Fatal("prekey signature verified as a context signature")
	}

	sig, err := id.SignWithContext("any", spkBytes)
	if err != nil {
		t.Fatal(err)
	}
	if ed25519.Verify(pub.Sign, spkBytes, sig) {
		t.Fatal("context signature verified as a plain prekey signature")
	}
}

func TestEmptyContextRejected(t *testing.T) {
	id := newIdentity(t)
	if _, err := id.SignWithContext("", []byte("m")); !errors.Is(err, ErrNoContext) {
		t.Fatalf("want ErrNoContext, got %v", err)
	}
	sig := ed25519.Sign(id.sign, []byte("m"))
	if id.Public().VerifyWithContext("", []byte("m"), sig) {
		t.Fatal("empty context accepted in verification")
	}
}
