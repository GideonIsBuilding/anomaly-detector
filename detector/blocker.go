package main

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"
)

// BanRecord tracks the full ban history for a single IP address.
// We use this to implement the backoff schedule.
type BanRecord struct {
	IP          string
	BanCount    int       // how many times this IP has been banned
	BannedAt    time.Time // when the current ban started
	ExpiresAt   time.Time // when the current ban should be lifted (zero = permanent)
	IsPermanent bool
}

// Blocker manages the iptables ban list and the audit log.
// It receives anomaly events and decides whether to ban an IP.
type Blocker struct {
	mu sync.Mutex

	// bans holds the current ban state for every IP we've ever blocked.
	bans map[string]*BanRecord

	cfg      *Config
	notifier *Notifier // we'll wire this in when we build notifier.go
	unbanner *Unbanner
}

// AuditEntry represents one structured line in the audit log.
type AuditEntry struct {
	Action    string  // BAN | UNBAN | BASELINE_RECALC
	IP        string  // empty for global events
	Condition string  // what triggered this entry
	Rate      float64 // current rate at time of event
	Baseline  float64 // effective baseline at time of event
	Duration  string  // ban duration — empty for non-ban events
	Timestamp time.Time
}

// NewBlocker creates and returns a ready-to-use Blocker.
func NewBlocker(cfg *Config, notifier *Notifier) *Blocker {
	return &Blocker{
		cfg:      cfg,
		bans:     make(map[string]*BanRecord),
		notifier: notifier,
	}
}

// Start receives anomaly events and acts on them.
// IP anomalies → iptables ban + Slack alert.
// Global anomalies → Slack alert only.
// Designed to be launched as a goroutine: go blocker.Start(anomalies)
func (b *Blocker) Start(anomalies <-chan AnomalyEvent) {
	fmt.Println("[blocker] started")

	for event := range anomalies {
		switch event.Type {

		case AnomalyTypeIP:
			b.handleIPAnomaly(event)

		case AnomalyTypeGlobal:
			b.handleGlobalAnomaly(event)
		}
	}
}

// handleIPAnomaly bans the offending IP via iptables and sends a Slack alert.
func (b *Blocker) handleIPAnomaly(event AnomalyEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Look up or create the ban record for this IP.
	record, exists := b.bans[event.IP]
	if !exists {
		record = &BanRecord{IP: event.IP}
		b.bans[event.IP] = record
	}

	// Determine the ban duration based on how many times this IP
	// has been banned before — the backoff ladder from config.
	durations := b.cfg.Blocking.BanDurationsMinutes
	idx := record.BanCount
	if idx >= len(durations) {
		// Beyond the ladder — use the last entry (permanent = -1).
		idx = len(durations) - 1
	}
	durationMinutes := durations[idx]

	// Update the ban record.
	record.BanCount++
	record.BannedAt = time.Now()

	var durationStr string
	if durationMinutes == -1 {
		record.IsPermanent = true
		record.ExpiresAt = time.Time{} // zero value = never expires
		durationStr = "permanent"
	} else {
		record.IsPermanent = false
		record.ExpiresAt = time.Now().Add(time.Duration(durationMinutes) * time.Minute)
		durationStr = fmt.Sprintf("%d minutes", durationMinutes)
	}

	fmt.Printf("[blocker] banning IP %s for %s (ban #%d)\n",
		event.IP, durationStr, record.BanCount)

	// Add the iptables DROP rule.
	if err := addIPTablesRule(event.IP); err != nil {
		fmt.Printf("[blocker] iptables error for %s: %v\n", event.IP, err)
	}

	// Write the audit log entry.
	writeAuditLog(b.cfg, AuditEntry{
		Action:    "BAN",
		IP:        event.IP,
		Condition: event.Condition,
		Rate:      event.CurrentRate,
		Baseline:  event.Baseline,
		Duration:  durationStr,
		Timestamp: time.Now(),
	})

	// Send Slack alert — this runs in a goroutine so it never blocks the blocker.
	go b.notifier.SendBanAlert(event, durationStr)
	// Schedule the unban timer — but only after we've released the lock.
	// We pass the record by value to avoid a data race.
	recordCopy := *record
	go b.unbanner.ScheduleUnban(&recordCopy)
}

// handleGlobalAnomaly sends a Slack alert only — no IP to block.
func (b *Blocker) handleGlobalAnomaly(event AnomalyEvent) {
	fmt.Printf("[blocker] global anomaly — rate=%.2f baseline=%.2f | %s\n",
		event.CurrentRate, event.Baseline, event.Condition)

	writeAuditLog(b.cfg, AuditEntry{
		Action:    "GLOBAL_ANOMALY",
		Condition: event.Condition,
		Rate:      event.CurrentRate,
		Baseline:  event.Baseline,
		Timestamp: time.Now(),
	})

	go b.notifier.SendGlobalAlert(event)
}

// GetBans returns a snapshot of all current bans — used by the dashboard.
func (b *Blocker) GetBans() []BanRecord {
	b.mu.Lock()
	defer b.mu.Unlock()

	result := make([]BanRecord, 0, len(b.bans))
	for _, record := range b.bans {
		result = append(result, *record)
	}
	return result
}

// GetActiveBanCount returns how many IPs are currently banned.
func (b *Blocker) GetActiveBanCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	count := 0
	for _, record := range b.bans {
		if record.IsPermanent || time.Now().Before(record.ExpiresAt) {
			count++
		}
	}
	return count
}

// RemoveBan removes an IP from the internal ban map.
// Called by the unbanner after it removes the iptables rule.
func (b *Blocker) RemoveBan(ip string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.bans, ip)
}

// ── iptables helpers ───────────────────────────────────────────────────────

// addIPTablesRule adds a DROP rule for the given IP address.
func addIPTablesRule(ip string) error {
	// First check if the rule already exists to avoid duplicates.
	checkCmd := exec.Command("iptables", "-C", "INPUT", "-s", ip, "-j", "DROP")
	if checkCmd.Run() == nil {
		// Rule already exists — nothing to do.
		return nil
	}

	// Add the DROP rule.
	cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables -A failed: %v — output: %s", err, string(output))
	}
	return nil
}

// RemoveIPTablesRule removes the DROP rule for the given IP.
// Called by the unbanner.
func RemoveIPTablesRule(ip string) error {
	cmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables -D failed: %v — output: %s", err, string(output))
	}
	return nil
}

// ── audit log ─────────────────────────────────────────────────────────────

// writeAuditLog appends a structured entry to the audit log file.
// Format: [timestamp] ACTION ip | condition | rate | baseline | duration
func writeAuditLog(cfg *Config, entry AuditEntry) {
	// Use current time if none provided.
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	// Build the log line.
	line := fmt.Sprintf("[%s] %s %s | %s | rate=%.2f | baseline=%.2f | duration=%s\n",
		entry.Timestamp.UTC().Format(time.RFC3339),
		entry.Action,
		entry.IP,
		entry.Condition,
		entry.Rate,
		entry.Baseline,
		entry.Duration,
	)

	// Open the audit log file in append mode.
	// os.O_CREATE creates the file if it doesn't exist.
	// os.O_APPEND means we add to the end, never overwrite.
	// 0644 is the file permission (owner read/write, others read).
	file, err := os.OpenFile(cfg.Server.AuditLogPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		// If we can't write the audit log, print to stdout as fallback.
		fmt.Printf("[audit] could not open audit log: %v\n", err)
		fmt.Print("[audit] " + line)
		return
	}
	defer file.Close()

	if _, err := file.WriteString(line); err != nil {
		fmt.Printf("[audit] could not write audit log: %v\n", err)
	}
}

func (b *Blocker) SetUnbanner(u *Unbanner) {
	b.unbanner = u
}
