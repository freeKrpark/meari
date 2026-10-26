package wire

import (
	"github.com/freekrpark/meari/internal/ratchet"
	"github.com/freekrpark/meari/internal/x3dh"
)

const minCiphertext = 16

type Envelope struct {
	Init    *x3dh.InitialMessage
	Message *ratchet.Message
}

func (e *Envelope) MarshalBinary() ([]byte, error) {
	w := &writer{}
	w.byte(Version)
	if e.Init != nil {
		w.byte(kindPreKeyMessage)
		writeInit(w, e.Init)
	} else {
		w.byte(kindMessage)
	}
	w.bytes(e.Message.Header.Bytes())
	w.bytes(e.Message.Ciphertext)
	return w.b, nil
}

func (e *Envelope) UnmarshalBinary(b []byte) error {
	r := &reader{b: b}
	r.version()

	var init *x3dh.InitialMessage
	switch kind := r.byte(); {
	case r.err != nil:
	case kind == kindPreKeyMessage:
		init = readInit(r)
	case kind != kindMessage:
		r.err = ErrMalformed
	}

	h := ratchet.Header{DH: r.x25519(), PN: r.uint32(), N: r.uint32()}
	if r.err == nil && len(r.b) < minCiphertext {
		r.err = ErrTruncated
	}
	if r.err != nil {
		return r.err
	}

	e.Init = init
	e.Message = &ratchet.Message{Header: h, Ciphertext: append([]byte(nil), r.b...)}
	return nil
}

func writeInit(w *writer, m *x3dh.InitialMessage) {
	w.bytes(m.Identity.Sign)
	w.bytes(m.Identity.DH.Bytes())
	w.bytes(m.Ephemeral.Bytes())
	w.uint32(m.SignedPreKeyID)
	w.byte(boolByte(m.HasOneTimePreKey))
	if m.HasOneTimePreKey {
		w.uint32(m.OneTimePreKeyID)
	}
}

func readInit(r *reader) *x3dh.InitialMessage {
	m := &x3dh.InitialMessage{
		Identity:       x3dh.PublicIdentity{Sign: r.ed25519(), DH: r.x25519()},
		Ephemeral:      r.x25519(),
		SignedPreKeyID: r.uint32(),
	}
	if m.HasOneTimePreKey = r.flag(); m.HasOneTimePreKey {
		m.OneTimePreKeyID = r.uint32()
	}
	return m
}
