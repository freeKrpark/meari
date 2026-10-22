package kdf

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestRFC5869Case1(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt := unhex(t, "000102030405060708090a0b0c")
	info := string(unhex(t, "f0f1f2f3f4f5f6f7f8f9"))
	const want = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

	got := hex.EncodeToString(mustDerive(t, ikm, salt, info, 42))
	if got != want {
		t.Fatalf("okm\n got %s\nwant %s", got, want)
	}
}

func TestDeterministic(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	a := mustDerive(t, secret, nil, "Meari_test", KeySize)
	b := mustDerive(t, secret, nil, "Meari_test", KeySize)
	if !bytes.Equal(a, b) {
		t.Fatal("same inputs produced different keys")
	}
}

func TestDomainSeperation(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	enc := mustDerive(t, secret, nil, "Meari_encryption", KeySize)
	mac := mustDerive(t, secret, nil, "Meari_authentication", KeySize)
	if bytes.Equal(enc, mac) {
		t.Fatal("different info labels produced the same key")
	}
}

func TestSaltChangesOutput(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, 32)
	a := mustDerive(t, secret, nil, "Meari_test", KeySize)
	b := mustDerive(t, secret, []byte("salt"), "Meari_test", KeySize)
	if bytes.Equal(a, b) {
		t.Fatal("salt had no effect on the derived key")
	}
}

func TestOutputDiffersFromInput(t *testing.T) {
	secret := bytes.Repeat([]byte{0x42}, KeySize)
	k := mustDerive(t, secret, nil, "Meari_test", KeySize)
	if bytes.Equal(k, secret) {
		t.Fatal("derived key equals the input secret")
	}
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustDerive(t *testing.T, secret, salt []byte, info string, n int) []byte {
	t.Helper()
	k, err := Derive(secret, salt, info, n)
	if err != nil {
		t.Fatal(err)
	}
	return k
}
