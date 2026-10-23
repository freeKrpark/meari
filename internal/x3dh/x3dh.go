package x3dh

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"

	"github.com/freekrpark/meari/internal/dh"
	"github.com/freekrpark/meari/internal/kdf"
)

const info = "Meari_X3DH"

var (
	ErrInvalidSignature = errors.New("x3dh: invalid signed prekey signature")
	ErrPreKeyMismatch   = errors.New("x3dh: prekey does not match initial message")
)

type InitialMessage struct {
	Identity         PublicIdentity
	Ephemeral        *ecdh.PublicKey
	SignedPreKeyID   uint32
	HasOneTimePreKey bool
	OneTimePreKeyID  uint32
}

type Result struct {
	SharedKey      []byte
	AssociatedData []byte
}

type dhPair struct {
	priv *ecdh.PrivateKey
	pub  *ecdh.PublicKey
}

func Initiate(alice *Identity, bundle *Bundle) (*Result, *InitialMessage, error) {

	if !ed25519.Verify(bundle.Identity.Sign, bundle.SignedPreKey.Bytes(), bundle.SignedPreKeySignature) {
		return nil, nil, ErrInvalidSignature
	}

	ek, err := dh.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	pairs := []dhPair{
		{alice.dh, bundle.SignedPreKey},
		{ek.Private, bundle.Identity.DH},
		{ek.Private, bundle.SignedPreKey},
	}

	if bundle.HasOneTimePreKey {
		pairs = append(pairs, dhPair{ek.Private, bundle.OneTimePreKey})
	}
	sk, err := deriveSharedKey(pairs)
	if err != nil {
		return nil, nil, err
	}

	msg := &InitialMessage{
		Identity:         alice.Public(),
		Ephemeral:        ek.Public,
		SignedPreKeyID:   bundle.SignedPreKeyID,
		HasOneTimePreKey: bundle.HasOneTimePreKey,
		OneTimePreKeyID:  bundle.OneTimePreKeyID,
	}

	res := &Result{
		SharedKey:      sk,
		AssociatedData: associatedData(alice.Public(), bundle.Identity),
	}

	return res, msg, nil
}

// Respond runs Bob's side of X3DH. opk must be nil when msg did not use a
// one-time prekey.
//
// Respond does not delete opk. On success the caller must delete it
// permanently; otherwise a replayed initial message yields the same key again.
func Respond(bob *Identity, spk *SignedPreKey, opk *OneTimePreKey, msg *InitialMessage) (*Result, error) {
	if spk.ID != msg.SignedPreKeyID {
		return nil, ErrPreKeyMismatch
	}
	if msg.HasOneTimePreKey != (opk != nil) {
		return nil, ErrPreKeyMismatch
	}
	if opk != nil && opk.ID != msg.OneTimePreKeyID {
		return nil, ErrPreKeyMismatch
	}

	pairs := []dhPair{
		{spk.Private, msg.Identity.DH}, // DH1
		{bob.dh, msg.Ephemeral},        // DH2
		{spk.Private, msg.Ephemeral},   // DH3
	}
	if opk != nil {
		pairs = append(pairs, dhPair{opk.Private, msg.Ephemeral}) // DH4
	}

	sk, err := deriveSharedKey(pairs)
	if err != nil {
		return nil, err
	}
	return &Result{
		SharedKey:      sk,
		AssociatedData: associatedData(msg.Identity, bob.Public()),
	}, nil

}

func deriveSharedKey(pairs []dhPair) ([]byte, error) {
	km := make([]byte, 0, dh.SecretSize*(len(pairs)+1))
	km = append(km, bytes.Repeat([]byte{0xff}, dh.SecretSize)...)
	defer clear(km)

	for _, p := range pairs {
		s, err := dh.DH(p.priv, p.pub)
		if err != nil {
			return nil, err
		}
		km = append(km, s...)
		clear(s)
	}
	return kdf.Derive(km, nil, info, kdf.KeySize)
}

func associatedData(initiator, responder PublicIdentity) []byte {
	return append(initiator.Bytes(), responder.Bytes()...)
}
