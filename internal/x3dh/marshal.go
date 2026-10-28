package x3dh

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
)

var ErrBadKey = errors.New("x3dh: invalid saved key")

func (id *Identity) MarshalBinary() ([]byte, error) {
	out := make([]byte, 0, ed25519.SeedSize+32)
	out = append(out, id.sign.Seed()...)
	return append(out, id.dh.Bytes()...), nil
}

func (id *Identity) UnmarshalBinary(b []byte) error {
	if len(b) != ed25519.SeedSize+32 {
		return ErrBadKey
	}
	dhKey, err := ecdh.X25519().NewPrivateKey(b[ed25519.SeedSize:])
	if err != nil {
		return ErrBadKey
	}

	id.sign = ed25519.NewKeyFromSeed(b[:ed25519.SeedSize])
	id.dh = dhKey
	return nil
}
