package main

import (
	"fmt"
	"math"
	"sync"
	"time"
)

// AnomalyType tells the blocker what kind of anomaly was detected.
type AnomalyType string

const (
	AnomalyTypeIP     AnomalyType = "IP"     // single aggressive IP
	AnomalyTypeGlobal AnomalyType = "GLOBAL" // traffic spike across all IPs
)

// AnomalyEvent is sent into a channel whenever an anomaly is detected.
// The blocker receives this and decides what action to take.
type AnomalyEvent struct {
	Type        AnomalyType
	IP          string  // empty for global anomalies
	CurrentRate float64 // requests/sec that triggered the alert
	Baseline    float64 // what normal looks like
	ZScore      float64 // how many stddevs above normal
	Condition   string  // human-readable description of what fired
	DetectedAt  time.Time
}

// ipWindow tracks the sliding window for a single IP address.
type ipWindow struct {
	requests  []time.Time // timestamps of recent requests
	errors    []time.Time // timestamps of recent 4xx/5xx responses
	alerted   bool        // have we already fired an anomaly for this IP?
	alertedAt time.Time   // when the alert was fired (for cooldown)
}

// Detector holds the sliding window state for all IPs and globally.
// It compares current rates against the baseline and emits anomaly events.
type Detector struct {
	mu sync.Mutex

	// Per-IP sliding windows. Key is the IP string.
	ipWindows map[string]*ipWindow

	// Global sliding window — one timestamp per request from any IP.
	globalWindow []time.Time

	cfg      *Config
	baseline *Baseline
}

// NewDetector creates and returns a ready-to-use Detector.
func NewDetector(cfg *Config, baseline *Baseline) *Detector {
	return &Detector{
		cfg:       cfg,
		baseline:  baseline,
		ipWindows: make(map[string]*ipWindow),
	}
}

// Start begins processing log entries. It runs forever, receiving entries
// from the monitor and emitting anomaly events when thresholds are exceeded.
// Designed to be launched as a goroutine: go detector.Start(entries, anomalies)
func (d *Detector) Start(entries <-chan LogEntry, anomalies chan<- AnomalyEvent) {
	fmt.Println("[detector] started")

	// Process one log entry at a time as they arrive from the monitor.
	for entry := range entries {
		isError := entry.Status >= 400
		d.process(entry, isError, anomalies)
	}
}

// process handles a single log entry — updates windows, checks thresholds.
func (d *Detector) process(entry LogEntry, isError bool, anomalies chan<- AnomalyEvent) {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	windowDuration := time.Duration(d.cfg.Detection.SlidingWindowSeconds) * time.Second

	// ── 1. Update global sliding window ───────────────────────────────────

	// Add this request to the global window.
	d.globalWindow = append(d.globalWindow, now)

	// Evict entries older than the sliding window duration from the front.
	// This is the deque eviction — we chop off the left side.
	for len(d.globalWindow) > 0 && now.Sub(d.globalWindow[0]) > windowDuration {
		d.globalWindow = d.globalWindow[1:]
	}

	// ── 2. Update per-IP sliding window ───────────────────────────────────

	// Get or create the window for this IP.
	win, exists := d.ipWindows[entry.SourceIP]
	if !exists {
		win = &ipWindow{}
		d.ipWindows[entry.SourceIP] = win
	}

	// Add the request timestamp.
	win.requests = append(win.requests, now)

	// Evict old request timestamps from the front.
	for len(win.requests) > 0 && now.Sub(win.requests[0]) > windowDuration {
		win.requests = win.requests[1:]
	}

	// Track error timestamps separately for error surge detection.
	if isError {
		win.errors = append(win.errors, now)
	}

	// Evict old error timestamps from the front.
	for len(win.errors) > 0 && now.Sub(win.errors[0]) > windowDuration {
		win.errors = win.errors[1:]
	}

	// ── 3. Get current baseline stats ─────────────────────────────────────

	// We release and re-acquire the lock around GetStats because
	// baseline.GetStats() acquires its own internal lock.
	// Holding two locks at once risks deadlock.
	d.mu.Unlock()
	mean, stddev, errMean := d.baseline.GetStats()
	d.mu.Lock()

	// ── 4. Check global anomaly ────────────────────────────────────────────

	// Global rate = total requests in window / window size in seconds.
	globalRate := float64(len(d.globalWindow)) / float64(d.cfg.Detection.SlidingWindowSeconds)
	globalAnomaly, globalCondition, globalZScore := d.isAnomalous(globalRate, mean, stddev)

	if globalAnomaly {
		anomalies <- AnomalyEvent{
			Type:        AnomalyTypeGlobal,
			CurrentRate: globalRate,
			Baseline:    mean,
			ZScore:      globalZScore,
			Condition:   globalCondition,
			DetectedAt:  now,
		}
	}

	// ── 5. Check per-IP anomaly ────────────────────────────────────────────

	// Rate for this IP = its request count in the window / window seconds.
	ipRate := float64(len(win.requests)) / float64(d.cfg.Detection.SlidingWindowSeconds)

	// Check for error surge — if this IP has an elevated error rate,
	// tighten its detection thresholds automatically.
	ipErrRate := float64(len(win.errors)) / float64(d.cfg.Detection.SlidingWindowSeconds)
	tighten := ipErrRate >= errMean*d.cfg.Detection.ErrorSurgeMultiplier && errMean > 0

	// Use tightened thresholds if error surge detected.
	checkMean := mean
	checkStddev := stddev
	if tighten {
		// Reduce thresholds by 30% to make detection more sensitive for this IP.
		checkMean = mean * 0.7
		checkStddev = stddev * 0.7
		fmt.Printf("[detector] error surge detected for %s — tightening thresholds\n", entry.SourceIP)
	}

	ipAnomaly, ipCondition, ipZScore := d.isAnomalous(ipRate, checkMean, checkStddev)

	// Only alert once per IP per ban cycle — avoid alert flooding.
	// Once an IP is alerted, we wait for the blocker to clear the flag.
	if ipAnomaly && !win.alerted {
		win.alerted = true
		win.alertedAt = now

		anomalies <- AnomalyEvent{
			Type:        AnomalyTypeIP,
			IP:          entry.SourceIP,
			CurrentRate: ipRate,
			Baseline:    mean,
			ZScore:      ipZScore,
			Condition:   ipCondition,
			DetectedAt:  now,
		}
	}
}

// isAnomalous returns true if the given rate exceeds either the z-score
// threshold or the rate multiplier threshold — whichever fires first.
func (d *Detector) isAnomalous(rate, mean, stddev float64) (bool, string, float64) {
	// ── Z-score check ──────────────────────────────────────────────────────
	// Z-score answers: "how many standard deviations above normal is this?"
	// Formula: z = (current_rate - mean) / stddev
	// A z-score above 3.0 means statistically very unusual.
	var zScore float64
	if stddev > 0 {
		zScore = (rate - mean) / stddev
	}

	if zScore > d.cfg.Detection.ZScoreThreshold {
		return true,
			fmt.Sprintf("z-score=%.2f exceeds threshold=%.2f", zScore, d.cfg.Detection.ZScoreThreshold),
			zScore
	}

	// ── Rate multiplier check ──────────────────────────────────────────────
	// Simpler check: is the rate more than 5x the baseline mean?
	// This catches spikes even when stddev is very small.
	if mean > 0 && rate > mean*d.cfg.Detection.RateMultiplierThreshold {
		multiplier := rate / mean
		return true,
			fmt.Sprintf("rate=%.2f is %.1fx baseline mean=%.2f", rate, multiplier, mean),
			zScore
	}

	return false, "", 0
}

// ClearAlert resets the alerted flag for an IP when it gets unbanned.
// Called by the unbanner so the IP can be detected and banned again if needed.
func (d *Detector) ClearAlert(ip string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if win, exists := d.ipWindows[ip]; exists {
		win.alerted = false
	}
}

// GetTopIPs returns the top N IPs by request count in the current window.
// Used by the dashboard.
func (d *Detector) GetTopIPs(n int) []IPStat {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Collect all IPs and their current request counts.
	stats := make([]IPStat, 0, len(d.ipWindows))
	for ip, win := range d.ipWindows {
		stats = append(stats, IPStat{
			IP:       ip,
			Requests: len(win.requests),
		})
	}

	// Simple insertion sort — the list is small so this is fine.
	for i := 1; i < len(stats); i++ {
		for j := i; j > 0 && stats[j].Requests > stats[j-1].Requests; j-- {
			stats[j], stats[j-1] = stats[j-1], stats[j]
		}
	}

	// Return only the top N.
	if len(stats) > n {
		return stats[:n]
	}
	return stats
}

// IPStat holds a single IP and its request count — used by the dashboard.
type IPStat struct {
	IP       string
	Requests int
}

// GetGlobalRate returns the current global requests/sec — used by dashboard.
func (d *Detector) GetGlobalRate() float64 {
	d.mu.Lock()
	defer d.mu.Unlock()

	return float64(len(d.globalWindow)) / float64(d.cfg.Detection.SlidingWindowSeconds)
}

// computeZScore is a standalone helper exposed for testing.
func computeZScore(rate, mean, stddev float64) float64 {
	if stddev == 0 {
		return 0
	}
	return math.Abs(rate-mean) / stddev
}
