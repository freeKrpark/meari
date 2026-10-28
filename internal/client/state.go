package client

import (
	"crypto/ecdh"
	"encoding/json"
	"errors"

	"github.com/freekrpark/meari/internal/api"
	"github.com/freekrpark/meari/internal/ratchet"
	"github.com/freekrpark/meari/internal/x3dh"
)

type state struct {
	Server         string           `json:"server"`
	Identity       []byte           `json:"identity"`
	SignedPreKey   preKey           `json:"spk"`
	OneTimePreKeys []preKey         `json:"opks"`
	Peers          map[string]*peer `json:"peers"`
	LastTimestamp  int64            `json:"last_ts"`
}

type preKey struct {
	ID        uint32 `json:"id"`
	Private   []byte `json:"private"`
	Signature []byte `json:"sig,omitempty"`
}

type peer struct {
	Session       ratchet.State `json:"session"`
	PendingInit   *initMessage  `json:"pending_init,omitempty"`
	InitEphemeral []byte        `json:"init_ephemeral,omitempty"`
}

type initMessage struct {
	Identity         []byte `json:"identity"`
	Ephemeral        []byte `json:"ephemeral"`
	SignedPreKeyID   uint32 `json:"spk_id"`
	HasOneTimePreKey bool   `json:"has_opk"`
	OneTimePreKeyID  uint32 `json:"opk_id"`
}

var errCorruptState = errors.New("client: saved state is corrupt")

func toInitMessage(m *x3dh.InitialMessage) *initMessage {
	return &initMessage{
		Identity:         m.Identity.Bytes(),
		Ephemeral:        m.Ephemeral.Bytes(),
		SignedPreKeyID:   m.SignedPreKeyID,
		HasOneTimePreKey: m.HasOneTimePreKey,
		OneTimePreKeyID:  m.OneTimePreKeyID,
	}
}

func (m *initMessage) x3dh() (*x3dh.InitialMessage, error) {
	id, err := api.ParseIdentity(m.Identity)
	if err != nil {
		return nil, errCorruptState
	}
	eph, err := ecdh.X25519().NewPublicKey(m.Ephemeral)
	if err != nil {
		return nil, errCorruptState
	}
	return &x3dh.InitialMessage{
		Identity:         id,
		Ephemeral:        eph,
		SignedPreKeyID:   m.SignedPreKeyID,
		HasOneTimePreKey: m.HasOneTimePreKey,
		OneTimePreKeyID:  m.OneTimePreKeyID,
	}, nil
}

func newPreKey(id uint32, priv *ecdh.PrivateKey, sig []byte) preKey {
	return preKey{ID: id, Private: priv.Bytes(), Signature: sig}
}

func (p preKey) signed() (*x3dh.SignedPreKey, error) {
	priv, err := ecdh.X25519().NewPrivateKey(p.Private)
	if err != nil {
		return nil, errCorruptState
	}
	return &x3dh.SignedPreKey{ID: p.ID, Private: priv, Signature: p.Signature}, nil
}

func (p preKey) oneTime() (*x3dh.OneTimePreKey, error) {
	priv, err := ecdh.X25519().NewPrivateKey(p.Private)
	if err != nil {
		return nil, errCorruptState
	}
	return &x3dh.OneTimePreKey{ID: p.ID, Private: priv}, nil
}

func (s *state) marshal() ([]byte, error) { return json.Marshal(s) }

func unmarshalState(b []byte) (*state, error) {
	var s state
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, errCorruptState
	}
	if s.Peers == nil {
		s.Peers = map[string]*peer{}
	}
	return &s, nil
}
