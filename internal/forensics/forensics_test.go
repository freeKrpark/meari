package forensics

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"runtime"
	"testing"
)

func TestDumpFindsValueInMemory(t *testing.T) {
	keep := []byte(hex.EncodeToString(randomBytes(t, 16)))

	mem, err := Dump(os.Getpid())
	if errors.Is(err, ErrUnsupported) {
		t.Skipf("not supported on %s", runtime.GOOS)
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(mem) < 1<<20 {
		t.Fatalf("dump is only %d bytes; regions were missed", len(mem))
	}
	if Count(mem, keep) == 0 {
		t.Fatal("value known to be in memory was not found in the dump")
	}
	t.Logf("dumped %.1f MB", float64(len(mem))/1e6)
	runtime.KeepAlive(keep)
}

// A process listing more memory than MaxDump is refused before anything is
// allocated, instead of running the machine out of memory.
func TestReadRegionsRefusesTooMuch(t *testing.T) {
	regions := []region{{base: 0, size: MaxDump}, {base: MaxDump, size: 1}}
	_, err := readRegions(regions, func(region, []byte) int {
		t.Fatal("read called for a dump that is too large")
		return 0
	})
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

// Regions are copied in order, and a region that is only partly readable
// contributes only the bytes actually read.
func TestReadRegionsKeepsOrderAndPartialReads(t *testing.T) {
	data := map[uint64][]byte{
		0x1000: []byte("first"),
		0x2000: []byte("second-region"),
		0x3000: []byte("third"),
	}
	regions := []region{
		{base: 0x1000, size: 5},
		{base: 0x2000, size: 13},
		{base: 0x3000, size: 5},
	}
	got, err := readRegions(regions, func(r region, dst []byte) int {
		src := data[r.base]
		if r.base == 0x2000 {
			src = src[:6] // only "second" could be read
		}
		return copy(dst, src)
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte("firstsecondthird"); !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestNear(t *testing.T) {
	mem := []byte("xxPOST /v1/messages/bob HTTP/1.1\r\nMeari-Account: alice\r\nyy")
	if !Near(mem, []byte("POST /v1/messages/bob"), []byte("Meari-Account: alice"), 64) {
		t.Fatal("did not find header right after request line")
	}
	if Near(mem, []byte("POST /v1/messages/bob"), []byte("Meari-Account: alice"), 5) {
		t.Fatal("found header outside the window")
	}
	if Near(mem, []byte("POST /v1/messages/carol"), []byte("alice"), 64) {
		t.Fatal("matched a request line that is not there")
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}
