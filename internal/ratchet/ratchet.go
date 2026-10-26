package ratchet

import (
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"maps"

	"github.com/freekrpark/meari/internal/dh"
)

const (
	MaxSkip          = 1000
	maxStoredSkipped = 2000

	headerSize = 32 + 4 + 4
)

var (
	ErrCannotSendYet  = errors.New("ratchet: responder cannot send before receiving")
	ErrTooManySkipped = errors.New("ratchet: too many skipped messages")
	ErrDecrypt        = errors.New("ratchet: message authentication failed")
)

type Header struct {
	DH *ecdh.PublicKey
	PN uint32
	N  uint32
}

func (h Header) Bytes() []byte {
	b := make([]byte, 0, headerSize)
	b = append(b, h.DH.Bytes()...)
	b = binary.BigEndian.AppendUint32(b, h.PN)
	return binary.BigEndian.AppendUint32(b, h.N)
}

type Message struct {
	Header     Header
	Ciphertext []byte
}

type skippedKey struct {
	dh [32]byte
	n  uint32
}

type Session struct {
	dhs *ecdh.PrivateKey
	dhr *ecdh.PublicKey
	rk  []byte
	cks []byte
	ckr []byte
	ns  uint32
	nr  uint32
	pn  uint32
	ad  []byte

	skipped map[skippedKey][]byte
}

func NewInitiator(sk, ad []byte, remoteRatchetKey *ecdh.PublicKey) (*Session, error) {
	kp, err := dh.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	out, err := dh.DH(kp.Private, remoteRatchetKey)
	if err != nil {
		return nil, err
	}

	rk, cks, err := kdfRK(sk, out)
	if err != nil {
		return nil, err
	}

	return &Session{
		dhs:     kp.Private,
		dhr:     remoteRatchetKey,
		rk:      rk,
		cks:     cks,
		ad:      append([]byte(nil), ad...),
		skipped: map[skippedKey][]byte{},
	}, nil
}

func NewResponder(sk, ad []byte, ownRatchetKey *ecdh.PrivateKey) *Session {
	return &Session{
		dhs:     ownRatchetKey,
		rk:      append([]byte(nil), sk...),
		ad:      append([]byte(nil), ad...),
		skipped: map[skippedKey][]byte{},
	}
}

func (s *Session) Encrypt(plaintext []byte) (*Message, error) {
	if s.cks == nil {
		return nil, ErrCannotSendYet
	}

	var mk []byte
	s.cks, mk = kdfCK(s.cks)
	h := Header{DH: s.dhs.PublicKey(), PN: s.pn, N: s.ns}
	s.ns++

	ct, err := encrypt(mk, plaintext, s.associatedData(h))
	if err != nil {
		return nil, err
	}
	return &Message{Header: h, Ciphertext: ct}, nil
}

func (s *Session) Decrypt(m *Message) ([]byte, error) {
	next := s.clone()
	pt, err := next.decrypt(m)
	if err != nil {
		return nil, err
	}
	*s = *next
	return pt, nil
}

func (s *Session) decrypt(m *Message) ([]byte, error) {
	h := m.Header
	if h.DH == nil {
		return nil, ErrDecrypt
	}
	ad := s.associatedData(h)

	key := skippedKey{dh: [32]byte(h.DH.Bytes()), n: h.N}
	if mk, ok := s.skipped[key]; ok {
		delete(s.skipped, key)
		return open(mk, m.Ciphertext, ad)
	}

	if s.dhr == nil || !s.dhr.Equal(h.DH) {
		if err := s.skipMessageKeys(h.PN); err != nil {
			return nil, err
		}
		if err := s.dhRatchet(h); err != nil {
			return nil, err
		}
	}
	if err := s.skipMessageKeys(h.N); err != nil {
		return nil, err
	}

	var mk []byte
	s.ckr, mk = kdfCK(s.ckr)
	s.nr++
	return open(mk, m.Ciphertext, ad)
}

func (s *Session) skipMessageKeys(until uint32) error {
	if s.ckr == nil || until <= s.nr {
		return nil
	}
	n := int(until - s.nr)
	if n > MaxSkip || len(s.skipped)+n > maxStoredSkipped {
		return ErrTooManySkipped
	}
	for s.nr < until {
		var mk []byte
		s.ckr, mk = kdfCK(s.ckr)
		s.skipped[skippedKey{dh: [32]byte(s.dhr.Bytes()), n: s.nr}] = mk
		s.nr++
	}
	return nil
}

func (s *Session) dhRatchet(h Header) error {
	s.pn = s.ns
	s.ns, s.nr = 0, 0
	s.dhr = h.DH

	out, err := dh.DH(s.dhs, s.dhr)
	if err != nil {
		return err
	}
	if s.rk, s.ckr, err = kdfRK(s.rk, out); err != nil {
		return err
	}

	kp, err := dh.GenerateKeyPair()
	if err != nil {
		return err
	}
	s.dhs = kp.Private
	if out, err = dh.DH(s.dhs, s.dhr); err != nil {
		return err
	}
	s.rk, s.cks, err = kdfRK(s.rk, out)
	return err
}

func (s *Session) associatedData(h Header) []byte {
	return append(append([]byte(nil), s.ad...), h.Bytes()...)
}

func (s *Session) clone() *Session {
	c := *s
	c.skipped = maps.Clone(s.skipped)
	return &c
}

func open(mk, ct, ad []byte) ([]byte, error) {
	pt, err := decrypt(mk, ct, ad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}
