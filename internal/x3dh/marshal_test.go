package x3dh

import (
	"bytes"
	"errors"
	"testing"
)

func TestIdentityRoundTrip(t *testing.T) {
	id := newIdentity(t)
	b, err := id.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	var got Identity
	if err := got.UnmarshalBinary(b); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Public().Bytes(), id.Public().Bytes()) {
		t.Fatal("restored identity has a different public key")
	}

	spk, err := NewSignedPreKey(&got, 1)
	if err != nil {
		t.Fatal(err)
	}
	bundle := NewBundle(id, spk, nil)
	alice := newIdentity(t)
	ra, msg, err := Initiate(alice, bundle)
	if err != nil {
		t.Fatalf("prekey signed by restored identity rejected: %v", err)
	}
	rb, err := Respond(&got, spk, nil, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ra.SharedKey, rb.SharedKey) {
		t.Fatal("restored identity derived a different shared key")
	}
}

func TestIdentityUnmarshalRejectsBadInput(t *testing.T) {
	b, _ := newIdentity(t).MarshalBinary()
	for name, bad := range map[string][]byte{
		"empty": nil,
		"short": b[:63],
		"long":  append(bytes.Clone(b), 0),
	} {
		var id Identity
		if err := id.UnmarshalBinary(bad); !errors.Is(err, ErrBadKey) {
			t.Errorf("%s: want ErrBadKey, got %v", name, err)
		}
	}
}
