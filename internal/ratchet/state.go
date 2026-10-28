package ratchet

import (
	"bytes"
	"cmp"
	"crypto/ecdh"
	"errors"
	"slices"
)

var ErrBadState = errors.New("ratchet: invalid saved state")

type State struct {
	DHs     []byte       `json:"dhs"`
	DHr     []byte       `json:"dhr,omitempty"`
	RK      []byte       `json:"rk"`
	CKs     []byte       `json:"cks,omitempty"`
	CKr     []byte       `json:"ckr,omitempty"`
	Ns      uint32       `json:"ns"`
	Nr      uint32       `json:"nr"`
	PN      uint32       `json:"pn"`
	AD      []byte       `json:"ad"`
	Skipped []SkippedKey `json:"skipped,omitempty"`
}

type SkippedKey struct {
	DH []byte `json:"dh"`
	N  uint32 `json:"n"`
	MK []byte `json:"mk"`
}

func (s *Session) State() State {
	st := State{
		DHs: s.dhs.Bytes(),
		RK:  bytes.Clone(s.rk),
		CKs: bytes.Clone(s.cks),
		CKr: bytes.Clone(s.ckr),
		Ns:  s.ns, Nr: s.nr, PN: s.pn,
		AD: bytes.Clone(s.ad),
	}
	if s.dhr != nil {
		st.DHr = s.dhr.Bytes()
	}
	for k, mk := range s.skipped {
		st.Skipped = append(st.Skipped, SkippedKey{DH: bytes.Clone(k.dh[:]), N: k.n, MK: bytes.Clone(mk)})
	}
	// Map order is random; sorting makes the same session give the same snapshot.
	slices.SortFunc(st.Skipped, func(a, b SkippedKey) int {
		return cmp.Or(bytes.Compare(a.DH, b.DH), cmp.Compare(a.N, b.N))
	})
	return st
}

func Restore(st State) (*Session, error) {
	curve := ecdh.X25519()
	dhs, err := curve.NewPrivateKey(st.DHs)
	if err != nil {
		return nil, ErrBadState
	}

	s := &Session{
		dhs:     dhs,
		ns:      st.Ns,
		nr:      st.Nr,
		pn:      st.PN,
		skipped: make(map[skippedKey][]byte, len(st.Skipped)),
	}

	if st.DHr != nil {
		if s.dhr, err = curve.NewPublicKey(st.DHr); err != nil {
			return nil, ErrBadState
		}
	}

	if len(st.RK) != 32 || !optionalKey(st.CKs) || !optionalKey(st.CKr) || len(st.AD) == 0 {
		return nil, ErrBadState
	}

	if st.CKr != nil && st.DHr == nil {
		return nil, ErrBadState
	}
	s.rk, s.cks, s.ckr, s.ad = bytes.Clone(st.RK), bytes.Clone(st.CKs), bytes.Clone(st.CKr), bytes.Clone(st.AD)

	if len(st.Skipped) > maxStoredSkipped {
		return nil, ErrBadState
	}

	for _, sk := range st.Skipped {
		if len(sk.DH) != 32 || len(sk.MK) != 32 {
			return nil, ErrBadState
		}

		k := skippedKey{dh: [32]byte(sk.DH), n: sk.N}
		if _, dup := s.skipped[k]; dup {
			return nil, ErrBadState
		}
		s.skipped[k] = bytes.Clone(sk.MK)
	}
	return s, nil
}

func optionalKey(k []byte) bool {
	return k == nil || len(k) == 32
}
