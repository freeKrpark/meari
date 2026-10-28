package client

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/freekrpark/meari/internal/api"
	"github.com/freekrpark/meari/internal/auth"
	"github.com/freekrpark/meari/internal/ratchet"
	"github.com/freekrpark/meari/internal/vault"
	"github.com/freekrpark/meari/internal/wire"
	"github.com/freekrpark/meari/internal/x3dh"
)

const NumOneTimePreKeys = 20

const (
	MaxPlaintext = 16 << 10
	maxInbox     = 1000
	maxDelivery  = 64<<10 + api.MessageIDSize + 20
	maxResponse  = maxInbox*(maxDelivery+4) + 4
)

var (
	ErrExists          = errors.New("client: vault already exists; refusing to overwrite an identity")
	ErrWrongIdentity   = errors.New("client: server returned keys that do not belong to that account")
	ErrSenderMismatch  = errors.New("client: message identity does not match its sender")
	ErrUnknownPreKey   = errors.New("client: message uses a prekey we no longer have")
	ErrNoSession       = errors.New("client: message from someone with no session")
	ErrMessageTooLarge = errors.New("client: message too large")
)

type Client struct {
	path  string
	vault *vault.Vault
	st    *state
	id    *x3dh.Identity
	http  *http.Client
}

type Received struct {
	From auth.AccountID
	Text string
	Err  error
}

func Init(path, server string, password []byte, p vault.Params) (*Client, error) {
	if _, err := os.Stat(path); err == nil {
		return nil, ErrExists
	}

	id, err := x3dh.NewIdentity()
	if err != nil {
		return nil, err
	}
	idBytes, _ := id.MarshalBinary()
	spk, err := x3dh.NewSignedPreKey(id, 1)
	if err != nil {
		return nil, err
	}
	st := &state{
		Server:       server,
		Identity:     idBytes,
		SignedPreKey: newPreKey(spk.ID, spk.Private, spk.Signature),
		Peers:        map[string]*peer{},
	}
	bundles := [][]byte{wire.MarshalBundle(x3dh.NewBundle(id, spk, nil))}
	for i := range NumOneTimePreKeys {
		opk, err := x3dh.NewOneTimePreKey(uint32(100 + i))
		if err != nil {
			return nil, err
		}
		st.OneTimePreKeys = append(st.OneTimePreKeys, newPreKey(opk.ID, opk.Private, nil))
		bundles = append(bundles, wire.MarshalBundle(x3dh.NewBundle(id, spk, opk)))
	}

	v, err := vault.Create(password, p)
	if err != nil {
		return nil, err
	}

	c := &Client{path: path, vault: v, st: st, id: id, http: &http.Client{Timeout: 30 * time.Second}}

	if err := c.save(); err != nil {
		return nil, err
	}
	if _, err := c.call("PUT", api.PathAccounts, id.Public().Bytes(), false, http.StatusOK); err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	if _, err := c.call("PUT", api.PathBundles, api.EncodeList(bundles), true, http.StatusNoContent); err != nil {
		return nil, fmt.Errorf("upload bundles: %w", err)
	}
	return c, nil
}

func Open(path string, password []byte) (*Client, error) {
	file, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	v, plain, err := vault.Open(password, file)
	if err != nil {
		return nil, err
	}
	st, err := unmarshalState(plain)
	if err != nil {
		return nil, err
	}
	var id x3dh.Identity
	if err := id.UnmarshalBinary(st.Identity); err != nil {
		return nil, errCorruptState
	}
	return &Client{path: path, vault: v, st: st, id: &id, http: &http.Client{Timeout: 30 * time.Second}}, nil

}

func (c *Client) ID() auth.AccountID {
	return auth.IDFor(c.id.Public())
}

func (c *Client) Send(to auth.AccountID, text string) error {
	if len(text) > MaxPlaintext {
		return ErrMessageTooLarge
	}
	p, err := c.peerForSending(to)
	if err != nil {
		return err
	}
	sess, err := ratchet.Restore(p.Session)
	if err != nil {
		return errCorruptState
	}
	m, err := sess.Encrypt([]byte(text))
	if err != nil {
		return err
	}
	env := &wire.Envelope{Message: m}
	if p.PendingInit != nil {
		if env.Init, err = p.PendingInit.x3dh(); err != nil {
			return err
		}
	}
	body, _ := env.MarshalBinary()

	p.Session = sess.State()
	c.st.Peers[to.String()] = p
	if err := c.save(); err != nil {
		return err
	}
	_, err = c.call("POST", api.PathMessages+"/"+to.String(), body, true, http.StatusAccepted)
	return err
}

func (c *Client) Receive() ([]Received, error) {
	raw, err := c.call("GET", api.PathInbox, nil, true, http.StatusOK)
	if err != nil {
		return nil, err
	}
	items, err := api.DecodeList(raw, maxInbox, maxDelivery)
	if err != nil {
		return nil, err
	}

	var out []Received
	for _, it := range items {
		var d api.Delivery
		if err := d.UnmarshalBinary(it); err != nil {
			return out, err
		}
		text, err := c.open(d)
		out = append(out, Received{From: d.From, Text: text, Err: err})

		if err == nil {
			if err := c.save(); err != nil {
				return out, err
			}
		}
		if _, err := c.call("DELETE", api.PathInbox+"/"+hex.EncodeToString(d.ID[:]), nil, true, http.StatusNoContent); err != nil {
			return out, err
		}
	}
	return out, nil
}

func (c *Client) save() error {
	plain, err := c.st.marshal()
	if err != nil {
		return err
	}
	defer clear(plain)
	file, err := c.vault.Seal(plain)
	if err != nil {
		return err
	}
	return vault.WriteFile(c.path, file)
}

func (c *Client) peerForSending(to auth.AccountID) (*peer, error) {
	if p, ok := c.st.Peers[to.String()]; ok {
		return p, nil
	}
	raw, err := c.call("GET", api.PathBundles+"/"+to.String(), nil, true, http.StatusOK)
	if err != nil {
		return nil, fmt.Errorf("fetch bundle: %w", err)
	}
	bundle, err := wire.UnmarshalBundle(raw)
	if err != nil {
		return nil, err
	}
	// The point of key-derived IDs: the server cannot substitute keys.
	if !to.Matches(bundle.Identity) {
		return nil, ErrWrongIdentity
	}
	res, init, err := x3dh.Initiate(c.id, bundle)
	if err != nil {
		return nil, err
	}
	sess, err := ratchet.NewInitiator(res.SharedKey, res.AssociatedData, bundle.SignedPreKey)
	if err != nil {
		return nil, err
	}
	return &peer{Session: sess.State(), PendingInit: toInitMessage(init)}, nil
}

func (c *Client) call(method, path string, body []byte, sign bool, want int) ([]byte, error) {
	req, err := http.NewRequest(method, c.st.Server+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if sign {
		ts := max(time.Now().UnixNano(), c.st.LastTimestamp+1)
		c.st.LastTimestamp = ts
		if err := auth.Sign(req, c.id, body, ts); err != nil {
			return nil, err
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != want {
		return nil, fmt.Errorf("%s %s: %s", method, path, resp.Status)
	}
	return out, nil
}

func (c *Client) open(d api.Delivery) (string, error) {
	var env wire.Envelope
	if err := env.UnmarshalBinary(d.Data); err != nil {
		return "", err
	}
	from := d.From.String()
	p, usedOPK, err := c.peerForReceiving(d.From, env.Init)
	if err != nil {
		return "", err
	}
	sess, err := ratchet.Restore(p.Session)
	if err != nil {
		return "", errCorruptState
	}
	pt, err := sess.Decrypt(env.Message)
	if err != nil {
		return "", err
	}

	// Commit only after successful decryption.
	p.Session = sess.State()
	p.PendingInit = nil // they replied, so they have the session
	c.st.Peers[from] = p
	if usedOPK != nil {
		c.st.OneTimePreKeys = deletePreKey(c.st.OneTimePreKeys, *usedOPK)
	}
	return string(pt), nil
}

func (c *Client) peerForReceiving(from auth.AccountID, init *x3dh.InitialMessage) (p *peer, usedOPK *uint32, err error) {
	existing, ok := c.st.Peers[from.String()]
	if init == nil {
		if !ok {
			return nil, nil, ErrNoSession
		}
		return existing, nil, nil
	}

	// The server vouches for who sent this; the X3DH header must agree.
	if !from.Matches(init.Identity) {
		return nil, nil, ErrSenderMismatch
	}
	// A repeat of the X3DH that started the current session.
	if ok && bytes.Equal(existing.InitEphemeral, init.Ephemeral.Bytes()) {
		return existing, nil, nil
	}
	// Otherwise the sender started a new session, which replaces ours.
	//
	// Known stage 1 limit: if both sides start a session at the same time,
	// each replaces its own with the other's and the two no longer match.
	// Signal's Sesame algorithm exists to resolve exactly this.

	spk, err := c.st.SignedPreKey.signed()
	if err != nil {
		return nil, nil, err
	}
	if spk.ID != init.SignedPreKeyID {
		return nil, nil, ErrUnknownPreKey
	}
	var opk *x3dh.OneTimePreKey
	if init.HasOneTimePreKey {
		k, found := findPreKey(c.st.OneTimePreKeys, init.OneTimePreKeyID)
		if !found {
			// Already used: this is a replay, or a second session that
			// raced for the same key.
			return nil, nil, ErrUnknownPreKey
		}
		if opk, err = k.oneTime(); err != nil {
			return nil, nil, err
		}
		usedOPK = &init.OneTimePreKeyID
	}
	res, err := x3dh.Respond(c.id, spk, opk, init)
	if err != nil {
		return nil, nil, err
	}
	sess := ratchet.NewResponder(res.SharedKey, res.AssociatedData, spk.Private)
	return &peer{Session: sess.State(), InitEphemeral: init.Ephemeral.Bytes()}, usedOPK, nil
}

func findPreKey(keys []preKey, id uint32) (preKey, bool) {
	for _, k := range keys {
		if k.ID == id {
			return k, true
		}
	}
	return preKey{}, false
}

func deletePreKey(keys []preKey, id uint32) []preKey {
	out := keys[:0]
	for _, k := range keys {
		if k.ID != id {
			out = append(out, k)
		}
	}
	return out
}
