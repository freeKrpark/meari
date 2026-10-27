package server

import (
	"errors"
	"sync"

	"github.com/freekrpark/meari/internal/api"
	"github.com/freekrpark/meari/internal/auth"
	"github.com/freekrpark/meari/internal/x3dh"
)

var errInboxFull = errors.New("server: inbox full")

type Store interface {
	PutIdentity(auth.AccountID, x3dh.PublicIdentity)
	Identity(auth.AccountID) (x3dh.PublicIdentity, bool)

	SetBundles(id auth.AccountID, fallback []byte, oneTime [][]byte)
	TakeBundle(auth.AccountID) ([]byte, bool)

	Enqueue(to auth.AccountID, d api.Delivery, max int) error
	Inbox(auth.AccountID) []api.Delivery
	Ack(auth.AccountID, [api.MessageIDSize]byte) bool
}

type MemoryStore struct {
	mu         sync.Mutex
	identities map[auth.AccountID]x3dh.PublicIdentity
	fallback   map[auth.AccountID][]byte
	oneTime    map[auth.AccountID][][]byte
	inbox      map[auth.AccountID][]api.Delivery
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		identities: map[auth.AccountID]x3dh.PublicIdentity{},
		fallback:   map[auth.AccountID][]byte{},
		oneTime:    map[auth.AccountID][][]byte{},
		inbox:      map[auth.AccountID][]api.Delivery{},
	}
}

func (s *MemoryStore) PutIdentity(id auth.AccountID, p x3dh.PublicIdentity) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.identities[id] = p
}

func (s *MemoryStore) Identity(id auth.AccountID) (x3dh.PublicIdentity, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.identities[id]
	return p, ok
}

func (s *MemoryStore) SetBundles(id auth.AccountID, fallback []byte, oneTime [][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fallback[id] = fallback
	s.oneTime[id] = oneTime
}

func (s *MemoryStore) TakeBundle(id auth.AccountID) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ot := s.oneTime[id]; len(ot) > 0 {
		b := ot[len(ot)-1]
		ot[len(ot)-1] = nil
		s.oneTime[id] = ot[:len(ot)-1]
		return b, true
	}
	b, ok := s.fallback[id]
	return b, ok
}

func (s *MemoryStore) Enqueue(to auth.AccountID, d api.Delivery, max int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.inbox[to]) >= max {
		return errInboxFull
	}
	s.inbox[to] = append(s.inbox[to], d)
	return nil
}

func (s *MemoryStore) Inbox(id auth.AccountID) []api.Delivery {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]api.Delivery(nil), s.inbox[id]...)
}

func (s *MemoryStore) Ack(id auth.AccountID, mid [api.MessageIDSize]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	in := s.inbox[id]
	for i, d := range in {
		if d.ID == mid {
			s.inbox[id] = append(in[:i:i], in[i+1:]...)
			return true
		}
	}
	return false
}
