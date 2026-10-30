package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"time"

	"github.com/freekrpark/meari/internal/api"
	"github.com/freekrpark/meari/internal/auth"
	"github.com/freekrpark/meari/internal/forensics"
	"github.com/freekrpark/meari/internal/x3dh"
)

const (
	markerSize = 4 << 10
	probeSize  = 32
)

func main() {
	runs := flag.Int("runs", 3, "repetitions of each experiment")
	filler := flag.Int("filler", 200, "messages sent after the deletion in the \"more traffic\" experiments")
	flag.Parse()

	if err := lab(*runs, *filler); err != nil {
		log.Fatal(err)
	}
}

type experiment struct {
	wipe   bool
	filler int
}

// result is how many copies of each part of the marker were found.
type result struct {
	head, middle, tail int
	dumpMB             float64
}

func lab(runs, filler int) error {
	dir, err := os.MkdirTemp("", "meari-memlab-*")
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

	experiments := []experiment{
		{wipe: false, filler: 0},
		{wipe: true, filler: 0},
		{wipe: false, filler: filler},
		{wipe: true, filler: filler},
	}

	fmt.Printf("# Memory lab: what is left of a deleted message\n\n")
	fmt.Printf("A %d-byte random marker is sent as one message, fetched and deleted.\n", markerSize)
	fmt.Printf("Then the server's memory is dumped and searched for %d-byte slices\n", probeSize)
	fmt.Printf("from the start, middle and end of the marker. %d runs each.\n\n", runs)
	fmt.Printf("| wipe on delete | messages after | start | middle | end | dump MB |\n")
	fmt.Printf("| --- | --- | --- | --- | --- | --- |\n")

	for _, e := range experiments {
		var rs []result
		for range runs {
			r, err := runOnce(bin, e)
			if err != nil {
				return err
			}
			rs = append(rs, r)
		}
		fmt.Printf("| %v | %d | %s | %s | %s | %.0f |\n", e.wipe, e.filler,
			spread(rs, func(r result) int { return r.head }),
			spread(rs, func(r result) int { return r.middle }),
			spread(rs, func(r result) int { return r.tail }),
			rs[0].dumpMB)
	}
	fmt.Printf("\nEach cell is the number of copies found, as min-max over the runs.\n")
	return nil
}

func spread(rs []result, f func(result) int) string {
	vals := make([]int, len(rs))
	for i, r := range rs {
		vals[i] = f(r)
	}
	lo, hi := slices.Min(vals), slices.Max(vals)
	if lo == hi {
		return strconv.Itoa(lo)
	}
	return fmt.Sprintf("%d-%d", lo, hi)
}

func runOnce(bin string, e experiment) (result, error) {
	addr, err := freeAddr()
	if err != nil {
		return result{}, err
	}
	srv := exec.Command(bin, "-addr", addr, "-wipe="+strconv.FormatBool(e.wipe))
	if err := srv.Start(); err != nil {
		return result{}, err
	}
	defer func() {
		srv.Process.Kill()
		srv.Wait()
	}()
	base := "http://" + addr
	if err := waitUp(base); err != nil {
		return result{}, err
	}

	alice, err := newUser(base)
	if err != nil {
		return result{}, err
	}
	bob, err := newUser(base)
	if err != nil {
		return result{}, err
	}

	marker := random(markerSize)
	if err := alice.send(bob, marker); err != nil {
		return result{}, err
	}
	if err := bob.receiveAll(); err != nil {
		return result{}, err
	}
	for range e.filler {
		if err := alice.send(bob, random(markerSize)); err != nil {
			return result{}, err
		}
	}
	if e.filler > 0 {
		if err := bob.receiveAll(); err != nil {
			return result{}, err
		}
	}

	mem, err := forensics.Dump(srv.Process.Pid)
	if err != nil {
		return result{}, fmt.Errorf("dump server memory: %w", err)
	}
	mid := markerSize/2 - probeSize/2
	return result{
		head:   forensics.Count(mem, marker[:probeSize]),
		middle: forensics.Count(mem, marker[mid:mid+probeSize]),
		tail:   forensics.Count(mem, marker[markerSize-probeSize:]),
		dumpMB: float64(len(mem)) / 1e6,
	}, nil
}

type user struct {
	base   string
	id     *x3dh.Identity
	lastTS int64
}

func newUser(base string) (*user, error) {
	id, err := x3dh.NewIdentity()
	if err != nil {
		return nil, err
	}
	u := &user{base: base, id: id}
	if _, err := u.call("PUT", api.PathAccounts, id.Public().Bytes(), false, http.StatusOK); err != nil {
		return nil, fmt.Errorf("register: %w", err)
	}
	return u, nil
}

func (u *user) account() auth.AccountID { return auth.IDFor(u.id.Public()) }

func (u *user) send(to *user, body []byte) error {
	_, err := u.call("POST", api.PathMessages+"/"+to.account().String(), body, true, http.StatusAccepted)
	return err
}

// receiveAll fetches every pending message and deletes each one.
func (u *user) receiveAll() error {
	raw, err := u.call("GET", api.PathInbox, nil, true, http.StatusOK)
	if err != nil {
		return err
	}
	items, err := api.DecodeList(raw, 1000, 64<<10+64)
	if err != nil {
		return err
	}
	for _, it := range items {
		var d api.Delivery
		if err := d.UnmarshalBinary(it); err != nil {
			return err
		}
		if _, err := u.call("DELETE", api.PathInbox+"/"+hex.EncodeToString(d.ID[:]), nil, true, http.StatusNoContent); err != nil {
			return err
		}
	}
	return nil
}

func (u *user) call(method, path string, body []byte, sign bool, want int) ([]byte, error) {
	req, err := http.NewRequest(method, u.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if sign {
		u.lastTS = max(time.Now().UnixNano(), u.lastTS+1)
		if err := auth.Sign(req, u.id, body, u.lastTS); err != nil {
			return nil, err
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != want {
		return nil, fmt.Errorf("%s %s: %s", method, path, resp.Status)
	}
	return out, nil
}

func random(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func freeAddr() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	return l.Addr().String(), nil
}

func waitUp(base string) error {
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(base + api.PathInbox)
		if err == nil {
			resp.Body.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("server at %s did not start", base)
}
