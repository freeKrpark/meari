package forensics

import (
	"bytes"
	"errors"
)

// MaxDump bounds how much memory Dump will copy.
const MaxDump = 4 << 30

var (
	// ErrUnsupported is returned on platforms where Dump is not implemented.
	ErrUnsupported = errors.New("forensics: memory dumps are supported on Linux and Windows only")
	// ErrTooLarge is returned when the readable memory exceeds MaxDump.
	ErrTooLarge = errors.New("forensics: process memory exceeds MaxDump")
)

// region is one readable range of the target's address space.
type region struct {
	base, size uint64
}

// readRegions copies every region into one buffer, sized up front.
//
// The region list must be complete before this runs. If a process dumps
// itself while still walking its address space, each growth of the output
// buffer commits new memory further along, the walk reaches it and copies
// it, the buffer grows again, and the dump chases itself until memory runs
// out.
func readRegions(regions []region, read func(r region, dst []byte) int) ([]byte, error) {
	var total uint64
	for _, r := range regions {
		total += r.size
	}
	if total > MaxDump {
		return nil, ErrTooLarge
	}
	out := make([]byte, 0, total)
	for _, r := range regions {
		start := len(out)
		out = out[:start+int(r.size)]
		n := read(r, out[start:])
		out = out[:start+n]
	}
	return out, nil
}

// Count reports how many times needle occurs in mem.
func Count(mem, needle []byte) int {
	if len(needle) == 0 {
		return 0
	}
	return bytes.Count(mem, needle)
}

// Near reports whether b occurs within window bytes after some occurrence
// of a. It finds two values that were written together, such as a request
// line and a header of the same HTTP request.
func Near(mem, a, b []byte, window int) bool {
	for off := 0; ; {
		i := bytes.Index(mem[off:], a)
		if i < 0 {
			return false
		}
		start := off + i + len(a)
		end := min(start+window, len(mem))
		if bytes.Contains(mem[start:end], b) {
			return true
		}
		off = off + i + 1
	}
}
