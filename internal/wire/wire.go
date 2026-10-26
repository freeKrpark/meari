package wire

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
)

const Version = 1

const (
	kindMessage       = 1
	kindPreKeyMessage = 2

	keySize = 32
	sigSize = ed25519.SignatureSize
)

var (
	ErrTruncated = errors.New("wire: input too short")
	ErrVersion   = errors.New("wire: unsupported version")
	ErrMalformed = errors.New("wire: malformed input")
)

type writer struct{ b []byte }

func (w *writer) byte(v byte) {
	w.b = append(w.b, v)
}

func (w *writer) bytes(v []byte) {
	w.b = append(w.b, v...)
}

func (w *writer) uint32(v uint32) {
	w.b = binary.BigEndian.AppendUint32(w.b, v)
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) next(n int) []byte {
	if r.err != nil {
		return nil
	}

	if len(r.b) < n {
		r.err = ErrTruncated
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) byte() byte {
	if b := r.next(1); b != nil {
		return b[0]
	}
	return 0
}

func (r *reader) uint32() uint32 {
	if b := r.next(4); b != nil {
		return binary.BigEndian.Uint32(b)
	}
	return 0
}

func (r *reader) x25519() *ecdh.PublicKey {
	b := r.next(keySize)
	if b == nil {
		return nil
	}
	pub, err := ecdh.X25519().NewPublicKey(b)
	if err != nil {
		r.err = ErrMalformed
		return nil
	}
	return pub
}

func (r *reader) ed25519() ed25519.PublicKey {
	if b := r.next(ed25519.PublicKeySize); b != nil {
		return ed25519.PublicKey(append([]byte(nil), b...))
	}
	return nil
}

func (r *reader) flag() bool {
	switch r.byte() {
	case 0:
		return false
	case 1:
		return true
	default:
		if r.err == nil {
			r.err = ErrMalformed
		}
		return false
	}
}

func (r *reader) version() {
	if v := r.byte(); r.err == nil && v != Version {
		r.err = ErrVersion
	}
}

// end fails if bytes are left over.
func (r *reader) end() {
	if r.err == nil && len(r.b) != 0 {
		r.err = ErrMalformed
	}
}

func boolByte(v bool) byte {
	if v {
		return 1
	}
	return 0
}
