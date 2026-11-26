package stats

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// System contains router resource usage displayed in the panel.
type System struct {
	CPU      float64       `json:"cpu"`     // %
	CPUKnown bool          `json:"-"`       // a delta for the current sample
	MemPct   float64       `json:"mem_pct"` // Used memory percentage.
	MemKnown bool          `json:"-"`       // both memory counters were read
	MemMB    int           `json:"mem_mb"`  // Total memory in MiB.
	Process  *ProcessUsage `json:"process,omitempty"`
}

// ProcessUsage covers the daemon and its embedded engine. CPU is absent until
// two consecutive samples can be compared against aggregate router CPU time.
type ProcessUsage struct {
	CPU      *float64 `json:"cpu,omitempty"`
	RSSBytes uint64   `json:"rss_bytes"`
}

// systemSampler derives CPU load from successive procfs counter samples.
type systemSampler struct {
	lastIdle, lastTotal uint64
	process             processSampler
	last                System
}

func (s *systemSampler) sample(root string) {
	idle, total, ok := readCPU(filepath.Join(root, "stat"))
	var sample System
	if ok && s.lastTotal > 0 && total > s.lastTotal && idle >= s.lastIdle {
		elapsed, idleDelta := total-s.lastTotal, idle-s.lastIdle
		if idleDelta <= elapsed {
			sample.CPU = round1(float64(elapsed-idleDelta) / float64(elapsed) * 100)
			sample.CPUKnown = true
		}
	}
	s.lastIdle, s.lastTotal = idle, total
	sample.Process = s.process.sample(filepath.Join(root, "self", "stat"), total)
	mem, available, known := readMem(filepath.Join(root, "meminfo"))
	sample.MemMB = int(mem / 1024)
	if known {
		sample.MemPct = round1(float64(mem-available) / float64(mem) * 100)
		sample.MemKnown = true
	}
	s.last = sample
}

func round1(v float64) float64 { return float64(int(v*10+0.5)) / 10 }

// readCPU reads aggregate procfs CPU counters, counting both idle and iowait as idle time.
func readCPU(path string) (idle, total uint64, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return 0, 0, false
	}
	fields := strings.Fields(sc.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, false
	}
	// Guest time is already included in user and nice.
	for i, v := range fields[1:min(len(fields), 9)] {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			return 0, 0, false
		}
		total += n
		if i == 3 || i == 4 { // idle + iowait
			idle += n
		}
	}
	return idle, total, true
}

// readMem reads the procfs counters in KiB. Used memory requires a valid
// total and a current MemAvailable value, which can be zero.
func readMem(path string) (total, avail uint64, ok bool) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	haveAvailable := false
	for sc.Scan() {
		k, v, found := strings.Cut(sc.Text(), ":")
		if !found || (k != "MemTotal" && k != "MemAvailable") {
			continue
		}
		fields := strings.Fields(v)
		if len(fields) == 0 {
			continue
		}
		n, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		if k == "MemTotal" {
			total = n
		} else {
			avail, haveAvailable = n, true
		}
	}
	return total, avail, sc.Err() == nil && total > 0 && haveAvailable && avail <= total
}
