package ratchet

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"

	"github.com/freekrpark/meari/internal/kdf"
)

const (
	rootInfo    = "Meari_Ratchet"
	messageInfo = "Meari_MessageKeys"
	nonceSize   = 12
)

func kdfRK(rk, dhOut []byte) (newRK, ck []byte, err error) {
	out, err := kdf.Derive(dhOut, rk, rootInfo, 2*kdf.KeySize)
	if err != nil {
		return nil, nil, err
	}
	return out[:kdf.KeySize], out[kdf.KeySize:], nil
}

func kdfCK(ck []byte) (nextCK, mk []byte) {
	mac := func(b byte) []byte {
		h := hmac.New(sha256.New, ck)
		h.Write([]byte{b})
		return h.Sum(nil)
	}

	return mac(0x02), mac(0x01)
}

func newAEAD(mk []byte) (cipher.AEAD, []byte, error) {
	km, err := kdf.Derive(mk, nil, messageInfo, kdf.KeySize+nonceSize)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(km[:kdf.KeySize])
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	return aead, km[kdf.KeySize:], nil
}
func encrypt(mk, plaintext, ad []byte) ([]byte, error) {
	aead, nonce, err := newAEAD(mk)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, ad), nil
}

func decrypt(mk, ciphertext, ad []byte) ([]byte, error) {
	aead, nonce, err := newAEAD(mk)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, ad)
}
