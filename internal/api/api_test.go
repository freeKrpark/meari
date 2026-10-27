package api

import (
	"bytes"
	"testing"

	"github.com/freekrpark/meari/internal/x3dh"
)

func TestListRoundTrip(t *testing.T) {
	in := [][]byte{[]byte("a"), {}, []byte("bc")}
	out, err := DecodeList(EncodeList(in), 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != len(in) {
		t.Fatalf("got %d items, want %d", len(out), len(in))
	}
	for i := range in {
		if !bytes.Equal(in[i], out[i]) {
			t.Fatalf("item %d: got %q, want %q", i, out[i], in[i])
		}
	}
}

func TestDecodeListRejectsMalformed(t *testing.T) {
	good := EncodeList([][]byte{[]byte("a"), []byte("bc")})
	if _, err := DecodeList(good, 2, 2); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		b              []byte
		maxN, maxBytes int
	}{
		"too many items":  {good, 1, 2},
		"item too large":  {good, 2, 1},
		"truncated":       {good[:len(good)-1], 2, 2},
		"trailing bytes":  {append(bytes.Clone(good), 0), 2, 2},
		"empty":           {nil, 2, 2},
		"huge item count": {[]byte{0xff, 0xff, 0xff, 0xff}, 1 << 30, 2},
	} {
		if _, err := DecodeList(tc.b, tc.maxN, tc.maxBytes); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseIdentityRoundTrip(t *testing.T) {
	id, err := x3dh.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	b := id.Public().Bytes()
	p, err := ParseIdentity(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p.Bytes(), b) {
		t.Fatal("identity changed in round trip")
	}
	for _, bad := range [][]byte{nil, b[:63], append(bytes.Clone(b), 0)} {
		if _, err := ParseIdentity(bad); err == nil {
			t.Errorf("accepted %d-byte identity", len(bad))
		}
	}
}

func TestDeliveryRoundTrip(t *testing.T) {
	d := Delivery{Data: []byte("opaque")}
	d.ID[0], d.From[0] = 1, 2
	b, _ := d.MarshalBinary()
	var got Delivery
	if err := got.UnmarshalBinary(b); err != nil {
		t.Fatal(err)
	}
	if got.ID != d.ID || got.From != d.From || !bytes.Equal(got.Data, d.Data) {
		t.Fatal("delivery changed in round trip")
	}
	if err := got.UnmarshalBinary(b[:10]); err == nil {
		t.Fatal("truncated delivery accepted")
	}
}
