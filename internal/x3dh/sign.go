package x3dh

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
)

var ErrNoContext = errors.New("x3dh: signing context must not be empty")

func (id *Identity) SignWithContext(context string, msg []byte) ([]byte, error) {
	if context == "" {
		return nil, ErrNoContext
	}
	return id.sign.Sign(rand.Reader, msg, &ed25519.Options{Hash: crypto.Hash(0), Context: context})
}

func (p PublicIdentity) VerifyWithContext(context string, msg, sig []byte) bool {
	if context == "" {
		return false
	}
	return ed25519.VerifyWithOptions(p.Sign, msg, sig, &ed25519.Options{Hash: crypto.Hash(0), Context: context}) == nil
}
