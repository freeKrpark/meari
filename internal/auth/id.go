package auth

import (
	"crypto/sha256"
	"encoding/base32"
	"errors"

	"github.com/freekrpark/meari/internal/x3dh"
)

const (
	idSize    = 20
	idContext = "Meari_AccountID_v1"
)

var ErrInvalidID = errors.New("auth: invalid account ID")
var idEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

type AccountID [idSize]byte

func IDFor(p x3dh.PublicIdentity) AccountID {
	h := sha256.New()
	h.Write([]byte(idContext))
	h.Write(p.Bytes())
	return AccountID(h.Sum(nil)[:idSize])
}

func (id AccountID) Matches(p x3dh.PublicIdentity) bool {
	return IDFor(p) == id
}

func (id AccountID) String() string {
	return idEncoding.EncodeToString(id[:])
}

func ParseAccountID(s string) (AccountID, error) {
	var id AccountID
	b, err := idEncoding.DecodeString(s)
	if err != nil || len(b) != idSize {
		return id, ErrInvalidID
	}
	copy(id[:], b)

	if id.String() != s {
		return AccountID{}, ErrInvalidID
	}
	return id, nil
}
