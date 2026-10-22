package dh

import (
	"crypto/ecdh"
	"crypto/rand"
)

const SecretSize = 32

type KeyPair struct {
	Private *ecdh.PrivateKey
	Public  *ecdh.PublicKey
}

func GenerateKeyPair() (*KeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &KeyPair{Private: priv, Public: priv.PublicKey()}, nil
}

func DH(priv *ecdh.PrivateKey, pub *ecdh.PublicKey) ([]byte, error) {
	return priv.ECDH(pub)
}
