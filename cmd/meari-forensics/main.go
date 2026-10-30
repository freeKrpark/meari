package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"time"

	"github.com/freekrpark/meari/internal/api"
	"github.com/freekrpark/meari/internal/auth"
	"github.com/freekrpark/meari/internal/forensics"
	"github.com/freekrpark/meari/internal/seizure"
)

const requestWindow = 1024

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	dir, err := os.MkdirTemp("", "meari-forensics-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)

	bin := filepath.Join(dir, "meari-server")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, "github.com/freekrpark/meari/cmd/meari-server")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		return fmt.Errorf("build server: %w", err)
	}

	addr, err := freeAddr()
	if err != nil {
		return err
	}
	srv := exec.Command(bin, "-addr", addr)
	if err := srv.Start(); err != nil {
		return err
	}
	defer srv.Process.Kill()
	url := "http://" + addr
	if err := waitUp(url); err != nil {
		return err
	}

	sc, err := seizure.Play(url)
	if err != nil {
		return err
	}
	mem, err := forensics.Dump(srv.Process.Pid)
	if err != nil {
		return fmt.Errorf("dump server memory: %w", err)
	}
	report(mem, sc, srv.Process.Pid, addr)
	return nil
}

func report(mem []byte, sc *seizure.Scenario, pid int, serverAddr string) {
	p := func(format string, args ...any) { fmt.Printf(format, args...) }
	names := slices.Sorted(func(yield func(string) bool) {
		for n := range sc.IDs {
			if !yield(n) {
				return
			}
		}
	})
	sender := func(id auth.AccountID) []byte { return []byte(auth.HeaderAccount + ": " + id.String()) }
	recipient := func(id auth.AccountID) []byte { return []byte("POST " + api.PathMessages + "/" + id.String()) }

	p("# Memory forensics report\n\n")
	p("Server process %d: %.1f MB of readable memory, dumped after the\n", pid, float64(len(mem))/1e6)
	p("scenario finished. Every message that was read had been deleted.\n\n")

	p("## Plaintext\n\n")
	leaked := 0
	for _, text := range sc.Texts {
		n := forensics.Count(mem, []byte(text))
		leaked += n
		p("- %q: %d\n", text, n)
	}

	p("\n## Account IDs\n\n")
	p("| user | ID anywhere | as sender (auth header) | as recipient (request path) |\n")
	p("| --- | --- | --- | --- |\n")
	for _, n := range names {
		id := sc.IDs[n]
		p("| %s | %d | %d | %d |\n", n,
			forensics.Count(mem, []byte(id.String())),
			forensics.Count(mem, sender(id)),
			forensics.Count(mem, recipient(id)))
	}

	p("\n## Sender and recipient in the same leftover request\n\n")
	p("A request line followed within %d bytes by the sender's auth header.\n\n", requestWindow)
	var pairs [][2]string
	for _, to := range names {
		for _, from := range names {
			if from != to && forensics.Near(mem, recipient(sc.IDs[to]), sender(sc.IDs[from]), requestWindow) {
				pairs = append(pairs, [2]string{from, to})
				p("- %s -> %s\n", from, to)
			}
		}
	}
	if len(pairs) == 0 {
		p("- none\n")
	}

	del := sc.Deleted
	a, b := sc.Names[del.A], sc.Names[del.B]
	p("\n## A conversation that was delivered and deleted\n\n")
	p("%s and %s exchanged one message, which was read and deleted. The\n", a, b)
	p("server's own state (cmd/meari-seize) shows nothing between them.\n\n")
	paired := slices.ContainsFunc(pairs, func(pr [2]string) bool {
		return (pr[0] == a && pr[1] == b) || (pr[0] == b && pr[1] == a)
	})
	p("- %s and %s found in the same leftover request: %v\n", a, b, paired)
	for _, n := range []string{a, b} {
		p("- %s still in memory as a recipient: %v\n", n, forensics.Count(mem, recipient(sc.IDs[n])) > 0)
	}

	p("\n## Client network addresses\n\n")
	clients := map[string]bool{}
	for _, m := range regexp.MustCompile(`127\.0\.0\.1:\d{2,5}`).FindAll(mem, -1) {
		if s := string(m); s != serverAddr {
			clients[s] = true
		}
	}
	p("- distinct client addresses (127.0.0.1:port) in memory: %d\n", len(clients))
	p("  On a real deployment these are users' IP addresses.\n")

	p("\n## Summary\n\n")
	p("- plaintext occurrences: %d\n", leaked)
	p("- sender/recipient pairs recoverable from memory: %d\n", len(pairs))
}

func freeAddr() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	return l.Addr().String(), nil
}

// waitUp polls until the server answers. An unsigned inbox request is
// rejected with 401, which is enough to know it is listening.
func waitUp(url string) error {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url + api.PathInbox)
		if err == nil {
			resp.Body.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("server at %s did not start", url)
}
