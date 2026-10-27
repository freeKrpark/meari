package server

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"

	"github.com/freekrpark/meari/internal/api"
	"github.com/freekrpark/meari/internal/auth"
)

const (
	MaxBundles    = 200
	MaxBundleSize = 1 << 10
	MaxEnvelope   = 64 << 10
	MaxInbox      = 1000
)

type Server struct {
	store    Store
	verifier *auth.Verifier
	mux      *http.ServeMux

	MaxInbox int
}

func New(store Store) *Server {
	s := &Server{store: store, mux: http.NewServeMux(), MaxInbox: MaxInbox}
	s.verifier = &auth.Verifier{Lookup: store.Identity}

	s.mux.HandleFunc("PUT "+api.PathAccounts, s.register)
	s.mux.HandleFunc("PUT "+api.PathBundles, s.authed(MaxBundles*(MaxBundleSize+4)+4, s.putBundles))
	s.mux.HandleFunc("GET "+api.PathBundles+"/{id}", s.authed(0, s.getBundle))
	s.mux.HandleFunc("POST "+api.PathMessages+"/{id}", s.authed(MaxEnvelope, s.send))
	s.mux.HandleFunc("GET "+api.PathInbox, s.authed(0, s.inbox))
	s.mux.HandleFunc("DELETE "+api.PathInbox+"/{mid}", s.authed(0, s.ack))
	return s
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}
func readBody(w http.ResponseWriter, r *http.Request, limit int) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(limit)))
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "bad body", http.StatusBadRequest)
		}
		return nil, false
	}
	return body, true
}

type authedHandler func(w http.ResponseWriter, r *http.Request, from auth.AccountID, body []byte)

func (s *Server) authed(limit int, h authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := readBody(w, r, limit)
		if !ok {
			return
		}
		from, err := s.verifier.Verify(r, body)
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h(w, r, from, body)
	}
}
func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	body, ok := readBody(w, r, 64)
	if !ok {
		return
	}
	pub, err := api.ParseIdentity(body)
	if err != nil {
		http.Error(w, "bad identity", http.StatusBadRequest)
		return
	}
	id := auth.IDFor(pub)
	s.store.PutIdentity(id, pub)
	io.WriteString(w, id.String())
}

func (s *Server) putBundles(w http.ResponseWriter, r *http.Request, from auth.AccountID, body []byte) {
	items, err := api.DecodeList(body, MaxBundles, MaxBundleSize)
	if err != nil || len(items) == 0 {
		http.Error(w, "bad bundle list", http.StatusBadRequest)
		return
	}
	s.store.SetBundles(from, items[0], items[1:])
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getBundle(w http.ResponseWriter, r *http.Request, _ auth.AccountID, _ []byte) {
	id, err := auth.ParseAccountID(r.PathValue("id"))
	if err != nil {
		http.Error(w, "bad account", http.StatusBadRequest)
		return
	}
	b, ok := s.store.TakeBundle(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Write(b)
}

func (s *Server) send(w http.ResponseWriter, r *http.Request, from auth.AccountID, body []byte) {
	to, err := auth.ParseAccountID(r.PathValue("id"))
	if err != nil {
		http.Error(w, "bad account", http.StatusBadRequest)
		return
	}
	if _, ok := s.store.Identity(to); !ok {
		http.NotFound(w, r)
		return
	}
	d := api.Delivery{From: from, Data: body}
	if _, err := rand.Read(d.ID[:]); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.store.Enqueue(to, d, s.MaxInbox); err != nil {
		http.Error(w, "inbox full", http.StatusTooManyRequests)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) inbox(w http.ResponseWriter, r *http.Request, me auth.AccountID, _ []byte) {
	pending := s.store.Inbox(me)
	items := make([][]byte, 0, len(pending))
	for _, d := range pending {
		b, _ := d.MarshalBinary()
		items = append(items, b)
	}
	w.Write(api.EncodeList(items))
}

func (s *Server) ack(w http.ResponseWriter, r *http.Request, me auth.AccountID, _ []byte) {
	var mid [api.MessageIDSize]byte
	raw, err := hex.DecodeString(r.PathValue("mid"))
	if err != nil || len(raw) != len(mid) {
		http.Error(w, "bad message id", http.StatusBadRequest)
		return
	}
	copy(mid[:], raw)
	if !s.store.Ack(me, mid) {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
