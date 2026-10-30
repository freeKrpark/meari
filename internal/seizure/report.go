package seizure

import (
	"cmp"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/freekrpark/meari/internal/auth"
	"github.com/freekrpark/meari/internal/server"
	"github.com/freekrpark/meari/internal/wire"
)

const UploadedOneTimeKeys = 20

type Evidence string

const (
	FromField  Evidence = "sender field"
	X3DHHeader Evidence = "X3DH header"
)

type Message struct {
	To           auth.AccountID
	From         auth.AccountID
	Evidence     []Evidence
	Size         int
	PlaintextLen int
	FirstMessage bool
	RatchetKey   [32]byte
	N, PN        uint32
	Unparsed     bool
}

type Pair struct {
	A, B auth.AccountID
}

func pairOf(x, y auth.AccountID) Pair {
	if strings.Compare(x.String(), y.String()) > 0 {
		x, y = y, x
	}
	return Pair{x, y}
}

type Report struct {
	Accounts []auth.AccountID
	Messages []Message

	SessionsStarted map[auth.AccountID]int
	LastSeen        map[auth.AccountID]int64
}

func Analyze(s server.Seizure) *Report {
	r := &Report{
		Accounts:        slices.SortedFunc(maps.Keys(s.Store.Identities), cmpID),
		SessionsStarted: map[auth.AccountID]int{},
		LastSeen:        maps.Clone(s.LastSeen),
	}
	for id := range s.Store.Identities {
		if _, hasBundles := s.Store.Fallback[id]; hasBundles {
			if used := UploadedOneTimeKeys - len(s.Store.OneTime[id]); used > 0 {
				r.SessionsStarted[id] = used
			}
		}
	}
	for to, inbox := range s.Store.Inbox {
		for _, d := range inbox {
			r.Messages = append(r.Messages, analyzeMessage(to, d.From, d.Data))
		}
	}
	slices.SortFunc(r.Messages, func(a, b Message) int {
		return cmp.Or(cmpID(a.To, b.To), cmpID(a.From, b.From), cmp.Compare(a.PN, b.PN), cmp.Compare(a.N, b.N))
	})
	return r
}

func analyzeMessage(to, from auth.AccountID, data []byte) Message {
	m := Message{To: to, Size: len(data)}
	if from != (auth.AccountID{}) {
		m.From = from
		m.Evidence = append(m.Evidence, FromField)
	}
	var env wire.Envelope
	if err := env.UnmarshalBinary(data); err != nil {
		m.Unparsed = true
		return m
	}
	h := env.Message.Header
	m.RatchetKey = [32]byte(h.DH.Bytes())
	m.N, m.PN = h.N, h.PN
	m.PlaintextLen = len(env.Message.Ciphertext) - 16
	if env.Init != nil {
		m.FirstMessage = true
		id := auth.IDFor(env.Init.Identity)
		if m.From == (auth.AccountID{}) {
			m.From = id
		}
		if id == m.From {
			m.Evidence = append(m.Evidence, X3DHHeader)
		}
	}
	return m
}

func (r *Report) Pairs() []Pair {
	set := map[Pair]bool{}
	for _, m := range r.Messages {
		if m.From != (auth.AccountID{}) {
			set[pairOf(m.From, m.To)] = true
		}
	}
	return slices.SortedFunc(maps.Keys(set), func(a, b Pair) int {
		return cmp.Or(cmpID(a.A, b.A), cmpID(a.B, b.B))
	})
}

func (r *Report) SendersRevealedWithoutFromField() int {
	n := 0
	for _, m := range r.Messages {
		if slices.Contains(m.Evidence, X3DHHeader) {
			n++
		}
	}
	return n
}

func (r *Report) DistinctSizes() int {
	sizes := map[int]bool{}
	for _, m := range r.Messages {
		sizes[m.Size] = true
	}
	return len(sizes)
}

func (r *Report) Write(w io.Writer, names map[auth.AccountID]string) {
	name := func(id auth.AccountID) string {
		if id == (auth.AccountID{}) {
			return "(unknown)"
		}
		if n, ok := names[id]; ok {
			return fmt.Sprintf("%s (%s…)", n, id.String()[:8])
		}
		return id.String()
	}
	p := func(format string, args ...any) { fmt.Fprintf(w, format, args...) }

	p("# Seizure report\n\n")
	p("What someone who took the server would learn from its state and\n")
	p("Meari's public wire format.\n\n")

	p("## Accounts: %d\n\n", len(r.Accounts))
	for _, id := range r.Accounts {
		p("- %s\n", name(id))
	}

	p("\n## Who is in contact: %d pairs\n\n", len(r.Pairs()))
	for _, pr := range r.Pairs() {
		p("- %s and %s\n", name(pr.A), name(pr.B))
	}

	p("\n## Pending messages: %d\n\n", len(r.Messages))
	for _, m := range r.Messages {
		p("- to %s from %s", name(m.To), name(m.From))
		if len(m.Evidence) > 0 {
			ev := make([]string, len(m.Evidence))
			for i, e := range m.Evidence {
				ev[i] = string(e)
			}
			p(" [via %s]", strings.Join(ev, ", "))
		}
		p("\n")
		if m.Unparsed {
			p("  - %d bytes, format not recognised\n", m.Size)
			continue
		}
		p("  - %d bytes stored; the text is exactly %d bytes long\n", m.Size, m.PlaintextLen)
		if m.FirstMessage {
			p("  - first message of a new conversation (X3DH header)\n")
		}
		p("  - message %d of the sender's current chain; previous chain had %d\n", m.N, m.PN)
	}
	p("\n- distinct message sizes: %d\n", r.DistinctSizes())
	p("- senders still known without the sender field: %d of %d\n",
		r.SendersRevealedWithoutFromField(), len(r.Messages))

	p("\n## Conversations started with each account\n\n")
	p("One-time prekeys taken from bundles (each client uploads %d).\n\n", UploadedOneTimeKeys)
	for _, id := range r.Accounts {
		if n := r.SessionsStarted[id]; n > 0 {
			p("- %s: %d\n", name(id), n)
		}
	}

	p("\n## Last activity\n\n")
	ids := slices.SortedFunc(maps.Keys(r.LastSeen), func(a, b auth.AccountID) int {
		return cmp.Compare(r.LastSeen[a], r.LastSeen[b])
	})
	if len(ids) > 0 {
		first := r.LastSeen[ids[0]]
		for _, id := range ids {
			p("- %s: +%.3fs\n", name(id), float64(r.LastSeen[id]-first)/1e9)
		}
	}
}

func cmpID(a, b auth.AccountID) int { return strings.Compare(a.String(), b.String()) }
