package api

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/binary"
	"errors"

	"github.com/freekrpark/meari/internal/auth"
	"github.com/freekrpark/meari/internal/x3dh"
)

const (
	PathAccounts = "/v1/accounts"
	PathBundles  = "/v1/bundles"
	PathMessages = "/v1/messages"
	PathInbox    = "/v1/inbox"
)

const MessageIDSize = 16

var ErrMalformed = errors.New("api: malformed input")

func ParseIdentity(b []byte) (x3dh.PublicIdentity, error) {
	if len(b) != ed25519.PublicKeySize+32 {
		return x3dh.PublicIdentity{}, ErrMalformed
	}
	dhKey, err := ecdh.X25519().NewPublicKey(b[ed25519.PublicKeySize:])
	if err != nil {
		return x3dh.PublicIdentity{}, ErrMalformed
	}
	sign := ed25519.PublicKey(append([]byte(nil), b[:ed25519.PublicKeySize]...))
	return x3dh.PublicIdentity{Sign: sign, DH: dhKey}, nil
}

func EncodeList(items [][]byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, uint32(len(items)))
	for _, it := range items {
		b = binary.BigEndian.AppendUint32(b, uint32(len(it)))
		b = append(b, it...)
	}

	return b
}

func DecodeList(b []byte, maxItems, maxItemSize int) ([][]byte, error) {
	if len(b) < 4 {
		return nil, ErrMalformed
	}

	n := binary.BigEndian.Uint32(b)
	b = b[4:]
	if n > uint32(maxItems) {
		return nil, ErrMalformed
	}

	items := make([][]byte, 0, min(int(n), len(b)/4))

	for range n {
		if len(b) < 4 {
			return nil, ErrMalformed
		}
		l := binary.BigEndian.Uint32(b)
		b = b[4:]
		if l > uint32(maxItemSize) || uint32(len(b)) < l {
			return nil, ErrMalformed
		}
		items = append(items, append([]byte(nil), b[:l]...))
		b = b[l:]
	}

	if len(b) != 0 {
		return nil, ErrMalformed
	}

	return items, nil
}

type Delivery struct {
	ID   [MessageIDSize]byte
	From auth.AccountID
	Data []byte
}

func (d Delivery) MarshalBinary() ([]byte, error) {
	b := make([]byte, 0, MessageIDSize+len(d.From)+len(d.Data))
	b = append(b, d.ID[:]...)
	b = append(b, d.From[:]...)
	return append(b, d.Data...), nil
}

func (d *Delivery) UnmarshalBinary(b []byte) error {
	head := MessageIDSize + len(d.From)
	if len(b) < head {
		return ErrMalformed
	}
	copy(d.ID[:], b)
	copy(d.From[:], b[MessageIDSize:])
	d.Data = append([]byte(nil), b[head:]...)
	return nil
}
