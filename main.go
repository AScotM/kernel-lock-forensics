package main

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Metric struct {
	Name   string  `json:"name"`
	Value  float64 `json:"value"`
	Unit   string  `json:"unit,omitempty"`
	Source string  `json:"source"`
}
type Task struct {
	PID           int    `json:"pid"`
	TID           int    `json:"tid"`
	Name          string `json:"name"`
	State         string `json:"state"`
	Wchan         string `json:"wchan,omitempty"`
	Voluntary     uint64 `json:"voluntary_context_switches"`
	Involuntary   uint64 `json:"involuntary_context_switches"`
	Threads       int    `json:"threads"`
	KernelStackKB uint64 `json:"kernel_stack_kb,omitempty"`
	BlockedSignal string `json:"blocked_signal_mask,omitempty"`
}
type LockEntry struct {
	Address string `json:"address"`
	Type    string `json:"type"`
	Mode    string `json:"mode"`
	PID     string `json:"pid"`
	Device  string `json:"device"`
	Inode   string `json:"inode"`
	Range   string `json:"range"`
	Raw     string `json:"raw"`
}
type Finding struct {
	Severity string `json:"severity"`
	Category string `json:"category"`
	Message  string `json:"message"`
	Evidence string `json:"evidence,omitempty"`
}
type Snapshot struct {
	Time         time.Time      `json:"time"`
	Hostname     string         `json:"hostname"`
	Kernel       string         `json:"kernel"`
	DurationMS   int64          `json:"duration_ms"`
	Metrics      []Metric       `json:"metrics"`
	Tasks        []Task         `json:"tasks,omitempty"`
	Locks        []LockEntry    `json:"locks,omitempty"`
	WaitChannels map[string]int `json:"wait_channels"`
	States       map[string]int `json:"states"`
	Findings     []Finding      `json:"findings"`
	Errors       []string       `json:"errors,omitempty"`
}
type Config struct {
	Proc         string
	Sys          string
	Interval     time.Duration
	Count        int
	Format       string
	Output       string
	Top          int
	AllThreads   bool
	IncludeLocks bool
	PID          int
	MinBlocked   int
	CPUThreshold float64
	IOThreshold  float64
	Verbose      bool
}
type Rates struct {
	Elapsed float64            `json:"elapsed_seconds"`
	Values  map[string]float64 `json:"values_per_second"`
}
type Report struct {
	Version   string         `json:"version"`
	Config    map[string]any `json:"config"`
	Snapshots []Snapshot     `json:"snapshots"`
	Rates     []Rates        `json:"rates,omitempty"`
}

func read(path string) (string, error) { b, e := os.ReadFile(path); return string(b), e }
func uint(s string) uint64             { v, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 64); return v }
func number(s string) float64          { v, _ := strconv.ParseFloat(strings.TrimSpace(s), 64); return v }
func fieldsMap(data string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(data, "\n") {
		f := strings.Fields(l)
		if len(f) > 1 {
			m[strings.TrimSuffix(f[0], ":")] = strings.Join(f[1:], " ")
		}
	}
	return m
}
func first(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}
func metric(s *Snapshot, name string, v float64, unit, source string) {
	s.Metrics = append(s.Metrics, Metric{name, v, unit, source})
}
func issue(s *Snapshot, category string, e error) {
	if e != nil {
		s.Errors = append(s.Errors, category+": "+e.Error())
	}
}
func find(s *Snapshot, severity, category, message, evidence string) {
	s.Findings = append(s.Findings, Finding{severity, category, message, evidence})
}
func metricValue(s Snapshot, name string) (float64, bool) {
	for _, m := range s.Metrics {
		if m.Name == name {
			return m.Value, true
		}
	}
	return 0, false
}
func pressure(s *Snapshot, path, prefix string) {
	data, e := read(path)
	if e != nil {
		issue(s, prefix, e)
		return
	}
	for _, l := range strings.Split(strings.TrimSpace(data), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		for _, kv := range f[1:] {
			p := strings.SplitN(kv, "=", 2)
			if len(p) != 2 {
				continue
			}
			metric(s, prefix+"."+f[0]+"."+p[0], number(p[1]), map[bool]string{true: "microseconds", false: "percent"}[p[0] == "total"], path)
		}
	}
}
func counters(s *Snapshot, path, prefix string, filter map[string]bool) {
	data, e := read(path)
	if e != nil {
		issue(s, prefix, e)
		return
	}
	for _, l := range strings.Split(data, "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		key := strings.TrimSuffix(f[0], ":")
		if filter != nil && !filter[key] {
			continue
		}
		metric(s, prefix+"."+key, number(f[1]), "counter", path)
	}
}
func interrupts(s *Snapshot, path, prefix string) {
	data, e := read(path)
	if e != nil {
		issue(s, prefix, e)
		return
	}
	lines := strings.Split(data, "\n")
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		name := strings.TrimSuffix(f[0], ":")
		if !strings.HasSuffix(f[0], ":") {
			continue
		}
		sum := uint64(0)
		for _, v := range f[1:] {
			if _, err := strconv.ParseUint(v, 10, 64); err != nil {
				break
			}
			sum += uint(v)
		}
		metric(s, prefix+"."+name, float64(sum), "counter", path)
	}
}
func statusTask(proc string, pid, tid int) (Task, error) {
	base := filepath.Join(proc, strconv.Itoa(pid), "task", strconv.Itoa(tid))
	data, e := read(filepath.Join(base, "status"))
	if e != nil {
		return Task{}, e
	}
	m := fieldsMap(data)
	t := Task{PID: pid, TID: tid, Name: m["Name"], State: first(m["State"]), Voluntary: uint(first(m["voluntary_ctxt_switches"])), Involuntary: uint(first(m["nonvoluntary_ctxt_switches"])), Threads: int(uint(first(m["Threads"]))), KernelStackKB: uint(first(m["VmStk"])), BlockedSignal: m["SigBlk"]}
	t.Wchan, _ = read(filepath.Join(base, "wchan"))
	t.Wchan = strings.TrimSpace(t.Wchan)
	return t, nil
}
func collectTasks(s *Snapshot, c Config) {
	dirs, e := os.ReadDir(c.Proc)
	if e != nil {
		issue(s, "tasks", e)
		return
	}
	for _, d := range dirs {
		pid, e := strconv.Atoi(d.Name())
		if e != nil || pid < 1 || (c.PID > 0 && pid != c.PID) {
			continue
		}
		base := filepath.Join(c.Proc, d.Name())
		if !c.AllThreads {
			t, e := statusTask(c.Proc, pid, pid)
			if e == nil {
				s.Tasks = append(s.Tasks, t)
			}
			continue
		}
		threads, e := os.ReadDir(filepath.Join(base, "task"))
		if e != nil {
			continue
		}
		for _, td := range threads {
			tid, e := strconv.Atoi(td.Name())
			if e != nil {
				continue
			}
			t, e := statusTask(c.Proc, pid, tid)
			if e == nil {
				s.Tasks = append(s.Tasks, t)
			}
		}
	}
	for _, t := range s.Tasks {
		s.States[t.State]++
		w := t.Wchan
		if w == "" {
			w = "unknown"
		}
		s.WaitChannels[w]++
	}
	metric(s, "tasks.observed", float64(len(s.Tasks)), "tasks", c.Proc)
	metric(s, "tasks.uninterruptible", float64(s.States["D"]), "tasks", c.Proc)
	metric(s, "tasks.running", float64(s.States["R"]), "tasks", c.Proc)
	metric(s, "tasks.sleeping", float64(s.States["S"]), "tasks", c.Proc)
}
func collectLocks(s *Snapshot, c Config) {
	path := filepath.Join(c.Proc, "locks")
	f, e := os.Open(path)
	if e != nil {
		issue(s, "locks", e)
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 1024*1024)
	for sc.Scan() {
		l := sc.Text()
		f := strings.Fields(l)
		if len(f) < 8 {
			continue
		}
		if len(f) > 2 && f[1] == "->" {
			continue
		}
		s.Locks = append(s.Locks, LockEntry{Address: strings.TrimSuffix(f[0], ":"), Type: f[1], Mode: f[3], PID: f[4], Device: f[5], Inode: f[5], Range: strings.Join(f[6:], " "), Raw: l})
	}
	issue(s, "locks.scan", sc.Err())
	metric(s, "locks.visible", float64(len(s.Locks)), "locks", path)
}
func sysKernel(s *Snapshot, c Config) {
	paths := map[string]string{"kernel.sched_schedstats": "kernel.sched_schedstats", "kernel.hung_task_timeout_secs": "kernel.hung_task_timeout_secs", "kernel.watchdog": "kernel.watchdog", "kernel.softlockup_panic": "kernel.softlockup_panic", "kernel.hung_task_panic": "kernel.hung_task_panic", "kernel.pid_max": "kernel.pid_max", "kernel.threads-max": "kernel.threads-max"}
	for name, rel := range paths {
		data, e := read(filepath.Join(c.Proc, "sys", rel))
		if e == nil {
			metric(s, name, number(data), "setting", filepath.Join(c.Proc, "sys", rel))
		}
	}
}
func kernelVersion(proc string) string {
	data, _ := read(filepath.Join(proc, "sys", "kernel", "osrelease"))
	return strings.TrimSpace(data)
}
func collect(c Config) Snapshot {
	start := time.Now()
	host, _ := os.Hostname()
	s := Snapshot{Time: start, Hostname: host, Kernel: kernelVersion(c.Proc), Metrics: []Metric{}, Tasks: []Task{}, Locks: []LockEntry{}, WaitChannels: map[string]int{}, States: map[string]int{}, Findings: []Finding{}, Errors: []string{}}
	pressure(&s, filepath.Join(c.Proc, "pressure", "cpu"), "psi.cpu")
	pressure(&s, filepath.Join(c.Proc, "pressure", "io"), "psi.io")
	pressure(&s, filepath.Join(c.Proc, "pressure", "memory"), "psi.memory")
	counters(&s, filepath.Join(c.Proc, "stat"), "proc.stat", map[string]bool{"ctxt": true, "processes": true, "procs_running": true, "procs_blocked": true, "intr": true, "softirq": true})
	counters(&s, filepath.Join(c.Proc, "vmstat"), "vmstat", map[string]bool{"nr_dirty": true, "nr_writeback": true, "pgfault": true, "pgmajfault": true, "pswpin": true, "pswpout": true, "allocstall_normal": true, "pgscan_kswapd": true, "pgscan_direct": true})
	interrupts(&s, filepath.Join(c.Proc, "softirqs"), "softirq")
	collectTasks(&s, c)
	if c.IncludeLocks {
		collectLocks(&s, c)
	}
	sysKernel(&s, c)
	if v, ok := metricValue(s, "psi.cpu.some.avg10"); ok && v >= c.CPUThreshold {
		find(&s, "warning", "cpu_pressure", fmt.Sprintf("CPU PSI some avg10 %.2f%% exceeds threshold %.2f%%", v, c.CPUThreshold), "/proc/pressure/cpu")
	}
	if v, ok := metricValue(s, "psi.io.some.avg10"); ok && v >= c.IOThreshold {
		find(&s, "warning", "io_pressure", fmt.Sprintf("IO PSI some avg10 %.2f%% exceeds threshold %.2f%%", v, c.IOThreshold), "/proc/pressure/io")
	}
	if s.States["D"] >= c.MinBlocked {
		find(&s, "warning", "blocked_tasks", fmt.Sprintf("%d tasks observed in uninterruptible sleep", s.States["D"]), "/proc/PID/task/TID/status")
	}
	if len(s.Errors) > 0 {
		find(&s, "info", "partial_visibility", fmt.Sprintf("%d interfaces could not be read; results may be incomplete", len(s.Errors)), "permission or kernel configuration")
	}
	s.DurationMS = time.Since(start).Milliseconds()
	return s
}
func rates(a, b Snapshot) Rates {
	elapsed := b.Time.Sub(a.Time).Seconds()
	r := Rates{Elapsed: elapsed, Values: map[string]float64{}}
	if elapsed <= 0 {
		return r
	}
	for _, m := range b.Metrics {
		if m.Unit != "counter" {
			continue
		}
		old, ok := metricValue(a, m.Name)
		if ok && m.Value >= old {
			r.Values[m.Name] = (m.Value - old) / elapsed
		}
	}
	return r
}
func taskRank(tasks []Task, top int) []Task {
	copyTasks := append([]Task{}, tasks...)
	sort.Slice(copyTasks, func(i, j int) bool {
		a := copyTasks[i].Voluntary + copyTasks[i].Involuntary
		b := copyTasks[j].Voluntary + copyTasks[j].Involuntary
		if a == b {
			return copyTasks[i].PID < copyTasks[j].PID
		}
		return a > b
	})
	if top > 0 && len(copyTasks) > top {
		copyTasks = copyTasks[:top]
	}
	return copyTasks
}
func channelRank(m map[string]int, top int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] == m[keys[j]] {
			return keys[i] < keys[j]
		}
		return m[keys[i]] > m[keys[j]]
	})
	if top > 0 && len(keys) > top {
		keys = keys[:top]
	}
	return keys
}
func writeText(w io.Writer, r Report, c Config) {
	fmt.Fprintf(w, "scheduler lock forensics v%s\n", r.Version)
	for i, s := range r.Snapshots {
		fmt.Fprintf(w, "\nSNAPSHOT %d  %s  host=%s kernel=%s scan=%dms\n", i+1, s.Time.Format(time.RFC3339), s.Hostname, s.Kernel, s.DurationMS)
		fmt.Fprintf(w, "TASKS total=%d running=%d sleeping=%d uninterruptible=%d\n", len(s.Tasks), s.States["R"], s.States["S"], s.States["D"])
		for _, name := range []string{"psi.cpu.some.avg10", "psi.cpu.full.avg10", "psi.io.some.avg10", "psi.memory.some.avg10", "proc.stat.procs_running", "proc.stat.procs_blocked", "locks.visible"} {
			if v, ok := metricValue(s, name); ok {
				fmt.Fprintf(w, "  %-34s %12.2f\n", name, v)
			}
		}
		fmt.Fprintln(w, "WAIT CHANNELS")
		for _, name := range channelRank(s.WaitChannels, c.Top) {
			fmt.Fprintf(w, "  %-42s %d\n", name, s.WaitChannels[name])
		}
		fmt.Fprintln(w, "TOP TASKS BY LIFETIME CONTEXT SWITCHES")
		fmt.Fprintln(w, "  PID      TID      STATE   VOLUNTARY    INVOLUNTARY   WCHAN                 NAME")
		for _, t := range taskRank(s.Tasks, c.Top) {
			fmt.Fprintf(w, "  %-8d %-8d %-7s %-12d %-13d %-21.21s %s\n", t.PID, t.TID, t.State, t.Voluntary, t.Involuntary, t.Wchan, t.Name)
		}
		if c.IncludeLocks {
			fmt.Fprintf(w, "VISIBLE POSIX/FLOCK/OFD LOCKS: %d\n", len(s.Locks))
			if c.Verbose {
				for _, l := range s.Locks {
					fmt.Fprintln(w, "  "+l.Raw)
				}
			}
		}
		for _, f := range s.Findings {
			fmt.Fprintf(w, "FINDING [%s] %s: %s\n", strings.ToUpper(f.Severity), f.Category, f.Message)
		}
		if c.Verbose {
			for _, e := range s.Errors {
				fmt.Fprintf(w, "READ ERROR %s\n", e)
			}
		}
		if i > 0 && i-1 < len(r.Rates) {
			fmt.Fprintf(w, "RATES (%.2fs)\n", r.Rates[i-1].Elapsed)
			keys := make([]string, 0, len(r.Rates[i-1].Values))
			for k := range r.Rates[i-1].Values {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				fmt.Fprintf(w, "  %-34s %12.2f/s\n", k, r.Rates[i-1].Values[k])
			}
		}
	}
}
func writeCSV(w io.Writer, r Report) error {
	cw := csv.NewWriter(w)
	if e := cw.Write([]string{"timestamp", "host", "category", "name", "value", "unit", "source"}); e != nil {
		return e
	}
	for _, s := range r.Snapshots {
		for _, m := range s.Metrics {
			if e := cw.Write([]string{s.Time.Format(time.RFC3339Nano), s.Hostname, "metric", m.Name, strconv.FormatFloat(m.Value, 'f', -1, 64), m.Unit, m.Source}); e != nil {
				return e
			}
		}
		for name, n := range s.WaitChannels {
			if e := cw.Write([]string{s.Time.Format(time.RFC3339Nano), s.Hostname, "wchan", name, strconv.Itoa(n), "tasks", "/proc"}); e != nil {
				return e
			}
		}
	}
	cw.Flush()
	return cw.Error()
}
func run(c Config) error {
	if c.Count < 1 {
		return errors.New("count must be >= 1")
	}
	if c.Interval < 100*time.Millisecond && c.Count > 1 {
		return errors.New("interval must be >= 100ms")
	}
	if c.Top < 1 {
		return errors.New("top must be >= 1")
	}
	if c.Format != "text" && c.Format != "json" && c.Format != "csv" {
		return errors.New("format must be text, json, or csv")
	}
	ctx := make(chan os.Signal, 1)
	signal.Notify(ctx, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(ctx)
	r := Report{Version: "1.0.0", Config: map[string]any{"interval": c.Interval.String(), "count": c.Count, "all_threads": c.AllThreads, "include_locks": c.IncludeLocks, "pid": c.PID}, Snapshots: []Snapshot{}, Rates: []Rates{}}
	for i := 0; i < c.Count; i++ {
		if i > 0 {
			select {
			case <-ctx:
				i = c.Count
				continue
			case <-time.After(c.Interval):
			}
		}
		s := collect(c)
		if len(r.Snapshots) > 0 {
			r.Rates = append(r.Rates, rates(r.Snapshots[len(r.Snapshots)-1], s))
		}
		r.Snapshots = append(r.Snapshots, s)
	}
	var w io.Writer = os.Stdout
	if c.Output != "" {
		f, e := os.Create(c.Output)
		if e != nil {
			return e
		}
		defer f.Close()
		w = f
	}
	switch c.Format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	case "csv":
		return writeCSV(w, r)
	default:
		writeText(w, r, c)
		return nil
	}
}
func main() {
	c := Config{}
	flag.StringVar(&c.Proc, "proc", "/proc", "procfs root")
	flag.StringVar(&c.Sys, "sys", "/sys", "sysfs root")
	flag.DurationVar(&c.Interval, "interval", 2*time.Second, "sampling interval")
	flag.IntVar(&c.Count, "count", 1, "number of snapshots")
	flag.StringVar(&c.Format, "format", "text", "text, json or csv")
	flag.StringVar(&c.Output, "output", "", "output file, default stdout")
	flag.IntVar(&c.Top, "top", 15, "top tasks and wait channels")
	flag.BoolVar(&c.AllThreads, "threads", true, "inspect individual threads")
	flag.BoolVar(&c.IncludeLocks, "locks", true, "inspect /proc/locks")
	flag.IntVar(&c.PID, "pid", 0, "restrict task inspection to process ID")
	flag.IntVar(&c.MinBlocked, "blocked-threshold", 3, "uninterruptible tasks warning threshold")
	flag.Float64Var(&c.CPUThreshold, "cpu-psi-threshold", 20, "CPU PSI some avg10 warning percent")
	flag.Float64Var(&c.IOThreshold, "io-psi-threshold", 10, "IO PSI some avg10 warning percent")
	flag.BoolVar(&c.Verbose, "verbose", false, "include read errors and raw lock records")
	flag.Parse()
	if err := run(c); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	_ = runtime.GOOS
}
