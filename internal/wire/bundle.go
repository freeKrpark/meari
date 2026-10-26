package wire

import "github.com/freekrpark/meari/internal/x3dh"

func MarshalBundle(b *x3dh.Bundle) []byte {
	w := &writer{}
	w.byte(Version)
	w.bytes(b.Identity.Sign)
	w.bytes(b.Identity.DH.Bytes())
	w.uint32(b.SignedPreKeyID)
	w.bytes(b.SignedPreKey.Bytes())
	w.bytes(b.SignedPreKeySignature)
	w.byte(boolByte(b.HasOneTimePreKey))
	if b.HasOneTimePreKey {
		w.uint32(b.OneTimePreKeyID)
		w.bytes(b.OneTimePreKey.Bytes())
	}
	return w.b
}

// UnmarshalBundle decodes a bundle downloaded from the server. It checks only
// the format; x3dh.Initiate still verifies the signature.
func UnmarshalBundle(data []byte) (*x3dh.Bundle, error) {
	r := &reader{b: data}
	r.version()
	b := &x3dh.Bundle{
		Identity:              x3dh.PublicIdentity{Sign: r.ed25519(), DH: r.x25519()},
		SignedPreKeyID:        r.uint32(),
		SignedPreKey:          r.x25519(),
		SignedPreKeySignature: append([]byte(nil), r.next(sigSize)...),
	}
	if b.HasOneTimePreKey = r.flag(); b.HasOneTimePreKey {
		b.OneTimePreKeyID = r.uint32()
		b.OneTimePreKey = r.x25519()
	}
	r.end()
	if r.err != nil {
		return nil, r.err
	}
	return b, nil
}
