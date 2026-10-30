package forensics

import (
	"bufio"
	"bytes"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
)

func Dump(pid int) ([]byte, error) {
	maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil, err
	}
	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return nil, err
	}
	defer mem.Close()

	var regions []region
	sc := bufio.NewScanner(bytes.NewReader(maps))
	for sc.Scan() {
		// "start-end perms offset dev inode path"
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || fields[1][0] != 'r' {
			continue
		}
		bounds := strings.SplitN(fields[0], "-", 2)
		start, err1 := strconv.ParseUint(bounds[0], 16, 64)
		end, err2 := strconv.ParseUint(bounds[1], 16, 64)
		// Skip the kernel's vsyscall page, which is above the int64 range
		// that ReadAt accepts.
		if err1 != nil || err2 != nil || end > math.MaxInt64 {
			continue
		}
		regions = append(regions, region{base: start, size: end - start})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return readRegions(regions, func(r region, dst []byte) int {
		n, _ := mem.ReadAt(dst, int64(r.base)) // some regions, like [vvar], refuse reads
		return n
	})
}
