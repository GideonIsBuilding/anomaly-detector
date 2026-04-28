package main

import (
	"fmt"
	"math"
	"sync"
	"time"
)

// windowEntry represents the request count for one specific second.
// We build a slice of these to form our rolling 30-minute window.
type windowEntry struct {
	timestamp time.Time // which second this count belongs to
	count     int       // how many requests arrived in that second
	errCount  int       // how many of those were 4xx or 5xx errors
}

// HourSlot tracks per-second counts for a specific hour of the day.
// We keep one slot per hour (0–23) so we can prefer the current
// hour's baseline when it has enough data.
type HourSlot struct {
	hour        int
	mean        float64
	stddev      float64
	errorMean   float64
	sampleCount int // how many per-second buckets we've seen this hour
}

// Baseline is the rolling statistical engine.
// It learns what normal traffic looks like and exposes mean/stddev
// for the detector to compare against.
type Baseline struct {
	mu sync.Mutex // protects all fields below from concurrent access

	// Rolling window: one entry per second, kept for up to 30 minutes.
	// Old entries are evicted during Recalculate().
	window []windowEntry

	// Per-hour slots — map from hour (0–23) to its computed stats.
	hourSlots map[int]*HourSlot

	// The currently effective baseline values — what the detector uses.
	effectiveMean   float64
	effectiveStdDev float64
	effectiveErrMean float64

	// A temporary bucket for the current second's in-progress count.
	currentSecond   time.Time
	currentCount    int
	currentErrCount int

	// When we last ran a full recalculation.
	lastRecalc time.Time

	cfg *Config
}

// NewBaseline creates and returns a ready-to-use Baseline.
func NewBaseline(cfg *Config) *Baseline {
	return &Baseline{
		cfg:         cfg,
		hourSlots:   make(map[int]*HourSlot),
		lastRecalc:  time.Now(),
		// Set a sensible floor so detection doesn't fire on an empty baseline.
		effectiveMean:   1.0,
		effectiveStdDev: 1.0,
		effectiveErrMean: 0.1,
	}
}

// RecordRequest is called for every incoming log entry.
// It increments the count for the current second's bucket.
// isError should be true if the HTTP status code is 4xx or 5xx.
func (b *Baseline) RecordRequest(isError bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Truncate the current time to the nearest second.
	// This groups all requests in the same second into one bucket.
	now := time.Now().Truncate(time.Second)

	if now.Equal(b.currentSecond) {
		// Still within the same second — just increment the counter.
		b.currentCount++
		if isError {
			b.currentErrCount++
		}
	} else {
		// A new second has started. Flush the previous bucket into the window
		// (but only if it actually has a timestamp — skip the very first call).
		if !b.currentSecond.IsZero() {
			b.window = append(b.window, windowEntry{
				timestamp: b.currentSecond,
				count:     b.currentCount,
				errCount:  b.currentErrCount,
			})
		}
		// Reset for the new second.
		b.currentSecond = now
		b.currentCount = 1
		if isError {
			b.currentErrCount = 1
		} else {
			b.currentErrCount = 0
		}
	}
}

// Recalculate evicts old window entries and recomputes mean and stddev.
// It is designed to be called on a ticker — every 60 seconds.
func (b *Baseline) Recalculate() {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-time.Duration(b.cfg.Detection.BaselineWindowMinutes) * time.Minute)

	// Evict entries older than the baseline window (30 minutes).
	// We walk through and keep only entries that are within the window.
	fresh := b.window[:0] // reuse the same slice memory
	for _, entry := range b.window {
		if entry.timestamp.After(cutoff) {
			fresh = append(fresh, entry)
		}
	}
	b.window = fresh

	// Need a minimum number of data points before we trust the baseline.
	if len(b.window) < b.cfg.Detection.MinRequestsForBaseline {
		fmt.Println("[baseline] not enough data yet — keeping floor values")
		return
	}

	// Compute mean and stddev from the rolling window.
	mean, stddev := computeStats(b.window)
	errMean := computeErrorMean(b.window)

	// Update the per-hour slot for the current hour.
	hour := now.Hour()
	slot, exists := b.hourSlots[hour]
	if !exists {
		slot = &HourSlot{hour: hour}
		b.hourSlots[hour] = slot
	}
	slot.mean = mean
	slot.stddev = stddev
	slot.errorMean = errMean
	slot.sampleCount = len(b.window)

	// Prefer the current hour's stats if it has enough data.
	// Otherwise fall back to the full rolling window stats.
	if slot.sampleCount >= b.cfg.Detection.MinRequestsForBaseline {
		b.effectiveMean = slot.mean
		b.effectiveStdDev = slot.stddev
		b.effectiveErrMean = slot.errorMean
	} else {
		b.effectiveMean = mean
		b.effectiveStdDev = stddev
		b.effectiveErrMean = errMean
	}

	// Write an audit log entry for this recalculation.
	writeAuditLog(b.cfg, AuditEntry{
		Action:    "BASELINE_RECALC",
		Condition: fmt.Sprintf("window=%d samples", len(b.window)),
		Rate:      mean,
		Baseline:  b.effectiveMean,
	})

	fmt.Printf("[baseline] recalculated — mean=%.2f stddev=%.2f errMean=%.4f samples=%d\n",
		b.effectiveMean, b.effectiveStdDev, b.effectiveErrMean, len(b.window))

	b.lastRecalc = now
}

// GetStats returns the current effective mean and stddev.
// This is what the detector calls when making a decision.
func (b *Baseline) GetStats() (mean, stddev, errMean float64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.effectiveMean, b.effectiveStdDev, b.effectiveErrMean
}

// GetCurrentRate returns the number of requests in the last 60 seconds.
// Used by the dashboard to show the live global req/s.
func (b *Baseline) GetCurrentRate() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()

	cutoff := time.Now().Add(-60 * time.Second)
	total := 0
	for _, entry := range b.window {
		if entry.timestamp.After(cutoff) {
			total += entry.count
		}
	}
	return float64(total) / 60.0
}

// GetHourSlots returns a copy of the hourly slot map for the dashboard.
func (b *Baseline) GetHourSlots() map[int]*HourSlot {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Return a shallow copy so the dashboard doesn't need to hold the lock.
	copy := make(map[int]*HourSlot)
	for k, v := range b.hourSlots {
		slotCopy := *v
		copy[k] = &slotCopy
	}
	return copy
}

// ── helpers ────────────────────────────────────────────────────────────────

// computeStats calculates the mean and population standard deviation
// from a slice of window entries.
func computeStats(entries []windowEntry) (mean, stddev float64) {
	if len(entries) == 0 {
		return 0, 0
	}

	// Step 1: compute the mean (sum / count).
	sum := 0
	for _, e := range entries {
		sum += e.count
	}
	mean = float64(sum) / float64(len(entries))

	// Step 2: compute variance — the average squared distance from the mean.
	variance := 0.0
	for _, e := range entries {
		diff := float64(e.count) - mean
		variance += diff * diff
	}
	variance /= float64(len(entries))

	// Step 3: stddev is the square root of variance.
	stddev = math.Sqrt(variance)
	return mean, stddev
}

// computeErrorMean calculates the average error rate per second
// across all window entries.
func computeErrorMean(entries []windowEntry) float64 {
	if len(entries) == 0 {
		return 0
	}
	sum := 0
	for _, e := range entries {
		sum += e.errCount
	}
	return float64(sum) / float64(len(entries))
}
