package forensics

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func Dump(pid int) ([]byte, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid))
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)

	// Walk the whole address space first, read afterwards (see readRegions).
	var regions []region
	var addr uintptr
	for {
		var mbi windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(h, addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
			break // past the last region
		}
		if mbi.State == windows.MEM_COMMIT && readable(mbi.Protect) {
			regions = append(regions, region{base: uint64(mbi.BaseAddress), size: uint64(mbi.RegionSize)})
		}
		next := mbi.BaseAddress + mbi.RegionSize
		if next <= addr {
			break
		}
		addr = next
	}

	return readRegions(regions, func(r region, dst []byte) int {
		if len(dst) == 0 {
			return 0
		}
		var n uintptr
		// A partial read returns an error but still fills n bytes.
		_ = windows.ReadProcessMemory(h, uintptr(r.base), &dst[0], uintptr(len(dst)), &n)
		return int(n)
	})
}

func readable(protect uint32) bool {
	if protect&(windows.PAGE_NOACCESS|windows.PAGE_GUARD) != 0 {
		return false
	}
	return protect&(windows.PAGE_READONLY|windows.PAGE_READWRITE|windows.PAGE_WRITECOPY|
		windows.PAGE_EXECUTE_READ|windows.PAGE_EXECUTE_READWRITE|windows.PAGE_EXECUTE_WRITECOPY) != 0
}
