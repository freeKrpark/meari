package kdf

import (
	"crypto/hkdf"
	"crypto/sha256"
)

const KeySize = 32

func Derive(secret, salt []byte, info string, length int) ([]byte, error) {
	return hkdf.Key(sha256.New, secret, salt, info, length)
}
