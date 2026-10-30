package server

import (
	"bytes"
	"maps"

	"github.com/freekrpark/meari/internal/api"
	"github.com/freekrpark/meari/internal/auth"
	"github.com/freekrpark/meari/internal/x3dh"
)

type StoreSnapshot struct {
	Identities map[auth.AccountID]x3dh.PublicIdentity
	Fallback   map[auth.AccountID][]byte
	OneTime    map[auth.AccountID][][]byte
	Inbox      map[auth.AccountID][]api.Delivery
}

type Seizure struct {
	Store    StoreSnapshot
	LastSeen map[auth.AccountID]int64
}

func (s *Server) Seize() Seizure {
	return Seizure{Store: s.store.Snapshot(), LastSeen: s.verifier.LastSeen()}
}

func (s *MemoryStore) Snapshot() StoreSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := StoreSnapshot{
		Identities: maps.Clone(s.identities),
		Fallback:   map[auth.AccountID][]byte{},
		OneTime:    map[auth.AccountID][][]byte{},
		Inbox:      map[auth.AccountID][]api.Delivery{},
	}
	for id, b := range s.fallback {
		snap.Fallback[id] = bytes.Clone(b)
	}
	for id, list := range s.oneTime {
		for _, b := range list {
			snap.OneTime[id] = append(snap.OneTime[id], bytes.Clone(b))
		}
	}
	for id, list := range s.inbox {
		for _, d := range list {
			d.Data = bytes.Clone(d.Data)
			snap.Inbox[id] = append(snap.Inbox[id], d)
		}
	}
	return snap
}
