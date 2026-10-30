package seizure

import (
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"

	"github.com/freekrpark/meari/internal/auth"
	"github.com/freekrpark/meari/internal/client"
	"github.com/freekrpark/meari/internal/server"
	"github.com/freekrpark/meari/internal/vault"
)

type Scenario struct {
	Server  *server.Server
	Names   map[auth.AccountID]string
	IDs     map[string]auth.AccountID
	Truth   []Pair
	Texts   []string
	Deleted Pair
}

func RunScenario() (*Scenario, error) {
	srv := server.New(server.NewMemoryStore())
	ts := httptest.NewServer(srv)
	defer ts.Close()

	sc, err := Play(ts.URL)
	if err != nil {
		return nil, err
	}
	sc.Server = srv
	return sc, nil
}

func Play(url string) (*Scenario, error) {
	dir, err := os.MkdirTemp("", "meari-seizure-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	fast := vault.Params{Time: 1, MemoryKib: 64, Threads: 1}
	sc := &Scenario{Names: map[auth.AccountID]string{}, IDs: map[string]auth.AccountID{}}
	users := map[string]*client.Client{}
	for _, name := range []string{"alice", "bob", "carol", "dave", "eve"} {
		c, err := client.Init(filepath.Join(dir, name+".vault"), url, []byte(name), fast)
		if err != nil {
			return nil, fmt.Errorf("init %s: %w", name, err)
		}
		users[name] = c
		sc.Names[c.ID()] = name
		sc.IDs[name] = c.ID()
	}

	send := func(from, to, text string) error {
		sc.Texts = append(sc.Texts, text)
		if err := users[from].Send(users[to].ID(), text); err != nil {
			return fmt.Errorf("%s -> %s: %w", from, to, err)
		}
		return nil
	}
	recv := func(who string) error {
		msgs, err := users[who].Receive()
		if err != nil {
			return fmt.Errorf("%s receive: %w", who, err)
		}
		for _, m := range msgs {
			if m.Err != nil {
				return fmt.Errorf("%s receive: %w", who, m.Err)
			}
		}
		return nil
	}

	for _, step := range []func() error{
		func() error { return send("alice", "bob", "are we still on for tonight?") },
		func() error { return recv("bob") },
		func() error { return send("bob", "alice", "yes, 8pm") },
		func() error { return recv("alice") },
		func() error { return send("alice", "bob", "see you") },
		func() error { return send("carol", "alice", "this is carol, call me") },
		func() error { return send("dave", "bob", "meeting moved to 3") },
		func() error { return send("dave", "bob", "bring the documents") },
		func() error { return send("carol", "dave", "the package arrived") },
		func() error { return recv("dave") },
	} {
		if err := step(); err != nil {
			return nil, err
		}
	}

	id := sc.IDs
	sc.Truth = []Pair{
		pairOf(id["alice"], id["bob"]),
		pairOf(id["alice"], id["carol"]),
		pairOf(id["bob"], id["dave"]),
		pairOf(id["carol"], id["dave"]),
	}
	sc.Deleted = pairOf(id["carol"], id["dave"])
	return sc, nil
}

func (sc *Scenario) Score(r *Report) (found, total int) {
	got := map[Pair]bool{}
	for _, p := range r.Pairs() {
		got[p] = true
	}
	for _, p := range sc.Truth {
		if got[p] {
			found++
		}
	}
	return found, len(sc.Truth)
}
