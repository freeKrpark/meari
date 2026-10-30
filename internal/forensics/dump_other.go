//go:build !linux && !windows

package forensics

func Dump(pid int) ([]byte, error) { return nil, ErrUnsupported }
