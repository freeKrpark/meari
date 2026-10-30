package seizure

import (
	"slices"
	"testing"
)

func run(t *testing.T) (*Scenario, *Report) {
	t.Helper()
	sc, err := RunScenario()
	if err != nil {
		t.Fatal(err)
	}
	return sc, Analyze(sc.Server.Seize())
}

func TestBaselineContactsRecovered(t *testing.T) {
	sc, r := run(t)
	if found, total := sc.Score(r); found != 3 || total != 4 {
		t.Fatalf("recovered %d of %d contacts, baseline is 3 of 4", found, total)
	}
}

func TestBaselineX3DHHeaderRevealsSender(t *testing.T) {
	_, r := run(t)
	if got := r.SendersRevealedWithoutFromField(); got != 3 {
		t.Fatalf("senders revealed by X3DH header: %d, baseline is 3", got)
	}
}

func TestBaselineExactLengthsLeak(t *testing.T) {
	_, r := run(t)
	var got []int
	for _, m := range r.Messages {
		got = append(got, m.PlaintextLen)
	}
	slices.Sort(got)
	// "see you", "meeting moved to 3", "bring the documents", "this is carol, call me"
	if want := []int{7, 18, 19, 22}; !slices.Equal(got, want) {
		t.Fatalf("plaintext lengths %v, want %v", got, want)
	}
	if n := r.DistinctSizes(); n != 4 {
		t.Fatalf("distinct sizes: %d, baseline is 4", n)
	}
}

func TestDeliveredMessagesLeaveNoContact(t *testing.T) {
	sc, r := run(t)
	if slices.Contains(r.Pairs(), sc.Deleted) {
		t.Fatal("contact recovered from a message that was already delivered")
	}
}

func TestBaselinePrekeysRevealNewConversations(t *testing.T) {
	sc, r := run(t)
	want := map[string]int{"alice": 1, "bob": 2, "dave": 1}
	for name, n := range want {
		if got := r.SessionsStarted[sc.IDs[name]]; got != n {
			t.Errorf("%s: %d conversations started, want %d", name, got, n)
		}
	}
	if len(r.SessionsStarted) != len(want) {
		t.Errorf("conversations started for %d accounts, want %d", len(r.SessionsStarted), len(want))
	}
}

func TestBaselineActivityTimesLeak(t *testing.T) {
	sc, r := run(t)
	if len(r.LastSeen) != len(sc.Names) {
		t.Fatalf("activity times for %d accounts, baseline is all %d", len(r.LastSeen), len(sc.Names))
	}
}

func TestSeizeReturnsACopy(t *testing.T) {
	sc, _ := run(t)
	s := sc.Server.Seize()
	for to := range s.Store.Inbox {
		for i := range s.Store.Inbox[to] {
			clear(s.Store.Inbox[to][i].Data)
		}
	}
	clear(s.LastSeen)

	again := Analyze(sc.Server.Seize())
	if again.SendersRevealedWithoutFromField() != 3 || len(again.LastSeen) != len(sc.Names) {
		t.Fatal("changing a seizure changed the server")
	}
}
