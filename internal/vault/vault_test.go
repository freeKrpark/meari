package vault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

var fast = Params{Time: 1, MemoryKib: 64, Threads: 1}

func create(t *testing.T, password string) *Vault {
	t.Helper()
	v, err := Create([]byte(password), fast)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func seal(t *testing.T, v *Vault, data string) []byte {
	t.Helper()
	f, err := v.Seal([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestRoundTrip(t *testing.T) {
	file := seal(t, create(t, "correct horse"), "identity keys and sessions")

	v, got, err := Open([]byte("correct horse"), file)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "identity keys and sessions" {
		t.Fatalf("got %q", got)
	}

	// The reopened vault can save again under the same password.
	again, err := v.Seal([]byte("updated"))
	if err != nil {
		t.Fatal(err)
	}
	if _, got, err := Open([]byte("correct horse"), again); err != nil || string(got) != "updated" {
		t.Fatalf("resealed: %q, %v", got, err)
	}
}

func TestWrongPassword(t *testing.T) {
	file := seal(t, create(t, "correct horse"), "secret")
	if _, _, err := Open([]byte("correct horsE"), file); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
}

func TestPlaintextNotInFile(t *testing.T) {
	file := seal(t, create(t, "pw"), "PRIVATE-KEY-MATERIAL")
	if bytes.Contains(file, []byte("PRIVATE-KEY-MATERIAL")) {
		t.Fatal("plaintext visible in vault file")
	}
}
func TestFreshNoncePerSeal(t *testing.T) {
	v := create(t, "pw")
	if bytes.Equal(seal(t, v, "same"), seal(t, v, "same")) {
		t.Fatal("two seals produced identical files")
	}
}

// Same password, different vaults: different salts, so different keys.
func TestFreshSaltPerVault(t *testing.T) {
	a, b := seal(t, create(t, "pw"), "x"), seal(t, create(t, "pw"), "x")
	if bytes.Equal(a[1:1+saltSize], b[1:1+saltSize]) {
		t.Fatal("two vaults share a salt")
	}
	if _, _, err := Open([]byte("pw"), append(a[:headerSize:headerSize], b[headerSize:]...)); !errors.Is(err, ErrDecrypt) {
		t.Fatal("ciphertext from one vault opened under another vault's header")
	}
}

// The header is authenticated: lowering the cost parameters or changing the
// salt must make decryption fail, not silently succeed.
func TestHeaderTamperingDetected(t *testing.T) {
	v, err := Create([]byte("pw"), Params{Time: 2, MemoryKib: 64, Threads: 1})
	if err != nil {
		t.Fatal(err)
	}
	file := seal(t, v, "secret")

	for name, at := range map[string]int{
		"salt":   1,
		"time":   1 + saltSize + 3,
		"memory": 1 + saltSize + 4 + 3,
	} {
		bad := bytes.Clone(file)
		bad[at] ^= 0x01
		if _, _, err := Open([]byte("pw"), bad); err == nil {
			t.Errorf("%s: tampered header accepted", name)
		}
	}
}

func TestCiphertextTamperingDetected(t *testing.T) {
	file := seal(t, create(t, "pw"), "secret")
	file[len(file)-1] ^= 0x01
	if _, _, err := Open([]byte("pw"), file); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("want ErrDecrypt, got %v", err)
	}
}

func TestRejectsBadFiles(t *testing.T) {
	good := seal(t, create(t, "pw"), "x")

	badVersion := bytes.Clone(good)
	badVersion[0] = version + 1

	// A crafted file asking for 4 GiB of memory must be refused before
	// Argon2 runs.
	hugeMemory := bytes.Clone(good)
	copy(hugeMemory[1+saltSize+4:], []byte{0xff, 0xff, 0xff, 0xff})

	zeroThreads := bytes.Clone(good)
	zeroThreads[headerSize-1] = 0

	for name, tc := range map[string]struct {
		file []byte
		want error
	}{
		"empty":        {nil, ErrFormat},
		"truncated":    {good[:headerSize+nonceSize-1], ErrFormat},
		"version":      {badVersion, ErrVersion},
		"huge memory":  {hugeMemory, ErrParams},
		"zero threads": {zeroThreads, ErrParams},
	} {
		if _, _, err := Open([]byte("pw"), tc.file); !errors.Is(err, tc.want) {
			t.Errorf("%s: want %v, got %v", name, tc.want, err)
		}
	}
}

func TestCreateRejectsBadParams(t *testing.T) {
	for _, p := range []Params{
		{Time: 0, MemoryKib: 64, Threads: 1},
		{Time: 1, MemoryKib: 64, Threads: 0},
		{Time: 1, MemoryKib: maxMemoryKib + 1, Threads: 1},
	} {
		if _, err := Create([]byte("pw"), p); !errors.Is(err, ErrParams) {
			t.Errorf("%+v: want ErrParams, got %v", p, err)
		}
	}
}

func TestDefaultParamsWork(t *testing.T) {
	if testing.Short() {
		t.Skip("uses 64 MiB of memory")
	}
	v, err := Create([]byte("pw"), DefaultParams)
	if err != nil {
		t.Fatal(err)
	}
	if _, got, err := Open([]byte("pw"), seal(t, v, "x")); err != nil || string(got) != "x" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestWriteFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.vault")
	if err := WriteFile(path, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(path, []byte("two")); err != nil {
		t.Fatal(err)
	}

	got, err := os.ReadFile(path)
	if err != nil || string(got) != "two" {
		t.Fatalf("got %q, %v", got, err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
	// Windows has no Unix permission bits to check.
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("permissions %o, want 600", perm)
		}
	}
}
