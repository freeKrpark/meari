// Package x3dh implements the X3DH key agreement
// (https://signal.org/docs/specifications/x3dh/).
//
// Deviation from the spec: Go has no XEdDSA, so a Meari identity is two keys,
// Ed25519 for signatures and X25519 for DH, instead of one Curve25519 key.
package x3dh

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"

	"github.com/freekrpark/meari/internal/dh"
)

const publicKeySize = 32

type Identity struct {
	sign ed25519.PrivateKey
	dh   *ecdh.PrivateKey
}

type PublicIdentity struct {
	Sign ed25519.PublicKey
	DH   *ecdh.PublicKey
}

func NewIdentity() (*Identity, error) {
	_, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	kp, err := dh.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return &Identity{sign: signPriv, dh: kp.Private}, nil
}

func (id *Identity) Public() PublicIdentity {
	return PublicIdentity{
		Sign: id.sign.Public().(ed25519.PublicKey),
		DH:   id.dh.PublicKey(),
	}
}

func (p PublicIdentity) Bytes() []byte {
	out := make([]byte, 0, ed25519.PublicKeySize+publicKeySize)
	out = append(out, p.Sign...)
	return append(out, p.DH.Bytes()...)
}

type SignedPreKey struct {
	ID        uint32
	Private   *ecdh.PrivateKey
	Signature []byte
}

func NewSignedPreKey(id *Identity, keyID uint32) (*SignedPreKey, error) {
	kp, err := dh.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(id.sign, kp.Public.Bytes())
	return &SignedPreKey{ID: keyID, Private: kp.Private, Signature: sig}, nil
}

type OneTimePreKey struct {
	ID      uint32
	Private *ecdh.PrivateKey
}

func NewOneTimePreKey(keyID uint32) (*OneTimePreKey, error) {
	kp, err := dh.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return &OneTimePreKey{ID: keyID, Private: kp.Private}, nil
}

type Bundle struct {
	Identity              PublicIdentity
	SignedPreKeyID        uint32
	SignedPreKey          *ecdh.PublicKey
	SignedPreKeySignature []byte
	HasOneTimePreKey      bool
	OneTimePreKeyID       uint32
	OneTimePreKey         *ecdh.PublicKey
}

func NewBundle(id *Identity, spk *SignedPreKey, opk *OneTimePreKey) *Bundle {
	b := &Bundle{
		Identity:              id.Public(),
		SignedPreKeyID:        spk.ID,
		SignedPreKey:          spk.Private.PublicKey(),
		SignedPreKeySignature: spk.Signature,
	}

	if opk != nil {
		b.HasOneTimePreKey = true
		b.OneTimePreKeyID = opk.ID
		b.OneTimePreKey = opk.Private.PublicKey()
	}
	return b
}
