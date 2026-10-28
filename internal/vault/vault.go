package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
)

const (
	version   = 1
	saltSize  = 16
	keySize   = 32
	nonceSize = 12

	headerSize = 1 + saltSize + 4 + 4 + 1

	maxTime      = 16
	maxMemoryKib = 1 << 20
)

type Params struct {
	Time      uint32
	MemoryKib uint32
	Threads   uint8
}

var DefaultParams = Params{Time: 3, MemoryKib: 64 * 1024, Threads: 4}

var (
	ErrDecrypt = errors.New("vault: wrong password or corrupted file")
	ErrFormat  = errors.New("vault: not a vault file")
	ErrVersion = errors.New("vault: unsupported version")
	ErrParams  = errors.New("vault: invalid parameters")
)

type Vault struct {
	header []byte
	aead   cipher.AEAD
}

func (p Params) valid() bool {
	return p.Time >= 1 && p.Time <= maxTime &&
		p.MemoryKib >= 8*uint32(p.Threads) && p.MemoryKib <= maxMemoryKib &&
		p.Threads >= 1
}

func Create(password []byte, p Params) (*Vault, error) {
	if !p.valid() {
		return nil, ErrParams
	}

	h := make([]byte, 0, headerSize)
	h = append(h, version)
	h = append(h, make([]byte, saltSize)...)
	if _, err := rand.Read(h[1 : 1+saltSize]); err != nil {
		return nil, err
	}

	h = binary.BigEndian.AppendUint32(h, p.Time)
	h = binary.BigEndian.AppendUint32(h, p.MemoryKib)
	h = append(h, p.Threads)
	return newVault(password, h, p)
}

func newVault(password, header []byte, p Params) (*Vault, error) {
	salt := header[1 : 1+saltSize]
	key := argon2.IDKey(password, salt, p.Time, p.MemoryKib, p.Threads, keySize)
	defer clear(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Vault{header: header, aead: aead}, nil
}

func Open(password, file []byte) (*Vault, []byte, error) {
	if len(file) < headerSize+nonceSize {
		return nil, nil, ErrFormat
	}
	if file[0] != version {
		return nil, nil, ErrVersion
	}
	header := append([]byte(nil), file[:headerSize]...)
	p := Params{
		Time:      binary.BigEndian.Uint32(header[1+saltSize:]),
		MemoryKib: binary.BigEndian.Uint32(header[1+saltSize+4:]),
		Threads:   header[headerSize-1],
	}
	if !p.valid() {
		return nil, nil, ErrParams
	}

	v, err := newVault(password, header, p)
	if err != nil {
		return nil, nil, err
	}
	nonce := file[headerSize : headerSize+nonceSize]
	plaintext, err := v.aead.Open(nil, nonce, file[headerSize+nonceSize:], header)
	if err != nil {
		return nil, nil, ErrDecrypt
	}
	return v, plaintext, nil
}

func (v *Vault) Seal(plaintext []byte) ([]byte, error) {
	out := make([]byte, 0, headerSize+nonceSize+len(plaintext)+v.aead.Overhead())
	out = append(out, v.header...)
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out = append(out, nonce...)
	return v.aead.Seal(out, nonce, plaintext, v.header), nil
}

func WriteFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vault-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
