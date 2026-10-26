package wire

import (
	"bytes"
	"errors"
	"testing"

	"github.com/freekrpark/meari/internal/ratchet"
	"github.com/freekrpark/meari/internal/x3dh"
)

type bob struct {
	id  *x3dh.Identity
	spk *x3dh.SignedPreKey
	opk *x3dh.OneTimePreKey
}

func newBob(t testing.TB, withOPK bool) *bob {
	t.Helper()
	id, err := x3dh.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	spk, err := x3dh.NewSignedPreKey(id, 7)
	if err != nil {
		t.Fatal(err)
	}
	b := &bob{id: id, spk: spk}
	if withOPK {
		if b.opk, err = x3dh.NewOneTimePreKey(42); err != nil {
			t.Fatal(err)
		}
	}
	return b
}

func marshal(t testing.TB, e *Envelope) []byte {
	t.Helper()
	b, err := e.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func unmarshal(t *testing.T, b []byte) *Envelope {
	t.Helper()
	var e Envelope
	if err := e.UnmarshalBinary(b); err != nil {
		t.Fatal(err)
	}
	return &e
}
func TestConversationOverBytes(t *testing.T) {
	for _, withOPK := range []bool{true, false} {
		b := newBob(t, withOPK)

		// Bob uploads his bundle; Alice downloads it.
		bundle, err := UnmarshalBundle(MarshalBundle(x3dh.NewBundle(b.id, b.spk, b.opk)))
		if err != nil {
			t.Fatal(err)
		}

		// Alice starts the session and sends the first message.
		alice, err := x3dh.NewIdentity()
		if err != nil {
			t.Fatal(err)
		}
		ra, init, err := x3dh.Initiate(alice, bundle)
		if err != nil {
			t.Fatal(err)
		}
		aliceSess, err := ratchet.NewInitiator(ra.SharedKey, ra.AssociatedData, bundle.SignedPreKey)
		if err != nil {
			t.Fatal(err)
		}
		m, err := aliceSess.Encrypt([]byte("hello bob"))
		if err != nil {
			t.Fatal(err)
		}
		first := unmarshal(t, marshal(t, &Envelope{Init: init, Message: m}))

		// Bob receives it.
		if first.Init == nil {
			t.Fatal("prekey message decoded without X3DH header")
		}
		rb, err := x3dh.Respond(b.id, b.spk, b.opk, first.Init)
		if err != nil {
			t.Fatal(err)
		}
		bobSess := ratchet.NewResponder(rb.SharedKey, rb.AssociatedData, b.spk.Private)
		pt, err := bobSess.Decrypt(first.Message)
		if err != nil || string(pt) != "hello bob" {
			t.Fatalf("bob got %q, %v", pt, err)
		}

		// Bob replies with an ordinary message.
		reply, err := bobSess.Encrypt([]byte("hi alice"))
		if err != nil {
			t.Fatal(err)
		}
		got := unmarshal(t, marshal(t, &Envelope{Message: reply}))
		if got.Init != nil {
			t.Fatal("ordinary message decoded with X3DH header")
		}
		pt, err = aliceSess.Decrypt(got.Message)
		if err != nil || string(pt) != "hi alice" {
			t.Fatalf("alice got %q, %v", pt, err)
		}
	}
}

func validEncodings(t testing.TB) map[string][]byte {
	t.Helper()
	b := newBob(t, true)
	alice, err := x3dh.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bundle := x3dh.NewBundle(b.id, b.spk, b.opk)
	ra, init, err := x3dh.Initiate(alice, bundle)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := ratchet.NewInitiator(ra.SharedKey, ra.AssociatedData, bundle.SignedPreKey)
	if err != nil {
		t.Fatal(err)
	}
	m, err := sess.Encrypt([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	return map[string][]byte{
		"message":        marshal(t, &Envelope{Message: m}),
		"prekey message": marshal(t, &Envelope{Init: init, Message: m}),
		"bundle":         MarshalBundle(bundle),
		"bundle no opk":  MarshalBundle(x3dh.NewBundle(b.id, b.spk, nil)),
	}
}

func decode(name string, b []byte) error {
	if name == "bundle" || name == "bundle no opk" {
		_, err := UnmarshalBundle(b)
		return err
	}
	var e Envelope
	return e.UnmarshalBinary(b)
}
func TestEveryTruncationRejected(t *testing.T) {
	for name, full := range validEncodings(t) {
		limit := len(full)
		if name == "message" || name == "prekey message" {
			limit -= len("x") // the plaintext validEncodings encrypts
		}
		for n := range limit {
			if err := decode(name, full[:n]); err == nil {
				t.Fatalf("%s: accepted %d of %d bytes", name, n, len(full))
			}
		}
	}
}

func TestTruncatedCiphertextFailsDecrypt(t *testing.T) {
	b := newBob(t, false)
	alice, err := x3dh.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	bundle := x3dh.NewBundle(b.id, b.spk, nil)
	ra, init, err := x3dh.Initiate(alice, bundle)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := ratchet.NewInitiator(ra.SharedKey, ra.AssociatedData, bundle.SignedPreKey)
	if err != nil {
		t.Fatal(err)
	}
	m, err := sess.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}

	full := marshal(t, &Envelope{Init: init, Message: m})
	got := unmarshal(t, full[:len(full)-1])

	rb, err := x3dh.Respond(b.id, b.spk, nil, got.Init)
	if err != nil {
		t.Fatal(err)
	}
	bobSess := ratchet.NewResponder(rb.SharedKey, rb.AssociatedData, b.spk.Private)
	if _, err := bobSess.Decrypt(got.Message); !errors.Is(err, ratchet.ErrDecrypt) {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
}

func TestRejectsWrongVersion(t *testing.T) {
	for name, b := range validEncodings(t) {
		b[0] = Version + 1
		if err := decode(name, b); !errors.Is(err, ErrVersion) {
			t.Fatalf("%s: want ErrVersion, got %v", name, err)
		}
	}
}

func TestRejectsUnknownKind(t *testing.T) {
	b := validEncodings(t)["message"]
	b[1] = 99
	if err := decode("message", b); !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed, got %v", err)
	}
}
func TestRejectsNonCanonicalFlag(t *testing.T) {
	b := validEncodings(t)["prekey message"]
	flagAt := 2 + 32 + 32 + 32 + 4
	if b[flagAt] != 1 {
		t.Fatalf("test setup: expected flag at offset %d", flagAt)
	}
	b[flagAt] = 2
	if err := decode("prekey message", b); !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed, got %v", err)
	}
}

func TestBundleRejectsTrailingBytes(t *testing.T) {
	b := append(validEncodings(t)["bundle"], 0)
	if _, err := UnmarshalBundle(b); !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed, got %v", err)
	}
}
func TestTamperedBundleFailsSignature(t *testing.T) {
	b := validEncodings(t)["bundle"]
	spkAt := 1 + 32 + 32 + 4
	b[spkAt] ^= 0x01

	bundle, err := UnmarshalBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	alice, err := x3dh.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := x3dh.Initiate(alice, bundle); !errors.Is(err, x3dh.ErrInvalidSignature) {
		t.Fatalf("want ErrInvalidSignature, got %v", err)
	}
}
func TestReencodeIsIdentical(t *testing.T) {
	for name, b := range validEncodings(t) {
		var out []byte
		if name == "bundle" || name == "bundle no opk" {
			bundle, err := UnmarshalBundle(b)
			if err != nil {
				t.Fatal(err)
			}
			out = MarshalBundle(bundle)
		} else {
			out = marshal(t, unmarshal(t, b))
		}
		if !bytes.Equal(b, out) {
			t.Fatalf("%s: re-encoding changed the bytes", name)
		}
	}
}
func FuzzEnvelope(f *testing.F) {
	for name, b := range validEncodings(f) {
		if name == "message" || name == "prekey message" {
			f.Add(b)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var e Envelope
		if e.UnmarshalBinary(data) != nil {
			return
		}
		out, err := e.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, out) {
			t.Fatalf("accepted input does not re-encode identically")
		}
	})
}

func FuzzBundle(f *testing.F) {
	for name, b := range validEncodings(f) {
		if name == "bundle" || name == "bundle no opk" {
			f.Add(b)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		b, err := UnmarshalBundle(data)
		if err != nil {
			return
		}
		if !bytes.Equal(data, MarshalBundle(b)) {
			t.Fatalf("accepted input does not re-encode identically")
		}
	})
}
