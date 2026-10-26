package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/freekrpark/meari/internal/x3dh"
)

const (
	HeaderAccount   = "Meari-Account"
	HeaderTimestamp = "Meari-Timestamp"
	HeaderSignature = "Meari-Signature"
)

const requestContext = "Meari request v1"

const DefaultMaxSkew = 5 * time.Minute

var (
	ErrMissingAuth   = errors.New("auth: missing authentication headers")
	ErrUnknownAcct   = errors.New("auth: unknown account")
	ErrBadSignature  = errors.New("auth: invalid signature")
	ErrStale         = errors.New("auth: timestamp outside allowed window")
	ErrReplay        = errors.New("auth: timestamp not newer than previous request")
	ErrBadAuthHeader = errors.New("auth: malformed authentication header")
)

func signedBytes(id AccountID, ts int64, method, uri string, body []byte) []byte {
	bodyHash := sha256.Sum256(body)
	var b []byte
	for _, f := range [][]byte{id[:], []byte(method), []byte(uri), bodyHash[:]} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(f)))
		b = append(b, f...)
	}
	return binary.BigEndian.AppendUint64(b, uint64(ts))
}

func Sign(req *http.Request, id *x3dh.Identity, body []byte, ts int64) error {
	acct := IDFor(id.Public())
	sig, err := id.SignWithContext(requestContext, signedBytes(acct, ts, req.Method, req.URL.RequestURI(), body))
	if err != nil {
		return err
	}
	req.Header.Set(HeaderAccount, acct.String())
	req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
	req.Header.Set(HeaderSignature, base64.StdEncoding.EncodeToString(sig))
	return nil
}

type Verifier struct {
	Lookup   func(AccountID) (x3dh.PublicIdentity, bool)
	Now      func() time.Time
	MaxSkew  time.Duration
	mu       sync.Mutex
	lastSeen map[AccountID]int64
}

func (v *Verifier) Verify(r *http.Request, body []byte) (AccountID, error) {
	acctStr, tsStr, sigStr := r.Header.Get(HeaderAccount), r.Header.Get(HeaderTimestamp), r.Header.Get(HeaderSignature)
	if acctStr == "" || tsStr == "" || sigStr == "" {
		return AccountID{}, ErrMissingAuth
	}
	acct, err := ParseAccountID(acctStr)
	if err != nil {
		return AccountID{}, ErrBadAuthHeader
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return AccountID{}, ErrBadAuthHeader
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(sigStr)
	if err != nil {
		return AccountID{}, ErrBadAuthHeader
	}

	now, skew := time.Now, DefaultMaxSkew
	if v.Now != nil {
		now = v.Now
	}
	if v.MaxSkew != 0 {
		skew = v.MaxSkew
	}
	if d := time.Duration(now().UnixNano() - ts); d > skew || d < -skew {
		return AccountID{}, ErrStale
	}

	pub, ok := v.Lookup(acct)
	if !ok {
		return AccountID{}, ErrUnknownAcct
	}
	if !pub.VerifyWithContext(requestContext, signedBytes(acct, ts, r.Method, r.RequestURI, body), sig) {
		return AccountID{}, ErrBadSignature
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if ts <= v.lastSeen[acct] {
		return AccountID{}, ErrReplay
	}
	if v.lastSeen == nil {
		v.lastSeen = map[AccountID]int64{}
	}
	v.lastSeen[acct] = ts
	return acct, nil

}
