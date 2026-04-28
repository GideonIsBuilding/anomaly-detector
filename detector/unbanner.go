package main

import (
	"fmt"
	"sync"
	"time"
)

// Unbanner watches all active bans and releases them when their
// duration expires, following the backoff schedule.
type Unbanner struct {
	mu sync.Mutex

	// scheduled tracks which IPs already have an unban timer running.
	// This prevents us from scheduling two timers for the same IP.
	scheduled map[string]bool

	cfg      *Config
	blocker  *Blocker
	detector *Detector
	notifier *Notifier
}

// NewUnbanner creates and returns a ready-to-use Unbanner.
func NewUnbanner(cfg *Config, blocker *Blocker, detector *Detector, notifier *Notifier) *Unbanner {
	return &Unbanner{
		cfg:       cfg,
		blocker:   blocker,
		detector:  detector,
		notifier:  notifier,
		scheduled: make(map[string]bool),
	}
}

// ScheduleUnban sets a timer to unban the given IP after its ban duration.
// If the ban is permanent, no timer is set.
// This is called by the blocker immediately after every ban.
func (u *Unbanner) ScheduleUnban(record *BanRecord) {
	u.mu.Lock()
	defer u.mu.Unlock()

	// Permanent bans are never scheduled for release.
	if record.IsPermanent {
		fmt.Printf("[unbanner] %s is permanently banned — no unban scheduled\n", record.IP)
		return
	}

	// Don't schedule a second timer if one is already running for this IP.
	if u.scheduled[record.IP] {
		fmt.Printf("[unbanner] timer already running for %s — skipping\n", record.IP)
		return
	}

	// Calculate how long until the ban expires.
	// ExpiresAt was set by the blocker when the ban was created.
	delay := time.Until(record.ExpiresAt)
	if delay <= 0 {
		// Ban already expired — unban immediately.
		go u.unban(record.IP)
		return
	}

	// Mark this IP as scheduled before launching the timer.
	u.scheduled[record.IP] = true

	ip := record.IP // capture for the closure below

	fmt.Printf("[unbanner] scheduled unban for %s in %.0f seconds\n",
		ip, delay.Seconds())

	// time.AfterFunc fires the function after the delay, in a new goroutine.
	// We don't need to track the timer — once it fires, it's done.
	time.AfterFunc(delay, func() {
		u.unban(ip)
	})
}

// unban removes the iptables rule, clears the ban from the blocker,
// resets the alert flag in the detector, and sends a Slack notification.
func (u *Unbanner) unban(ip string) {
	fmt.Printf("[unbanner] unbanning %s\n", ip)

	// ── 1. Remove the iptables DROP rule ──────────────────────────────────
	if err := RemoveIPTablesRule(ip); err != nil {
		// Log but don't stop — we still want to clean up internal state.
		fmt.Printf("[unbanner] iptables removal failed for %s: %v\n", ip, err)
	}

	// ── 2. Get the ban record before we remove it ──────────────────────────
	// We need the ban count to build the audit log message.
	bans := u.blocker.GetBans()
	var banCount int
	for _, b := range bans {
		if b.IP == ip {
			banCount = b.BanCount
			break
		}
	}

	// ── 3. Clear the scheduled flag ────────────────────────────────────────
	u.mu.Lock()
	delete(u.scheduled, ip)
	u.mu.Unlock()

	// ── 4. Remove from the blocker's ban map ──────────────────────────────
	u.blocker.RemoveBan(ip)

	// ── 5. Reset the detector's alert flag so this IP can be detected again ─
	u.detector.ClearAlert(ip)

	// ── 6. Determine what the next ban duration would be ──────────────────
	// This goes into the Slack message so the team knows what happens
	// if this IP misbehaves again.
	nextDuration := u.nextBanDuration(banCount)

	// ── 7. Write the audit log entry ──────────────────────────────────────
	writeAuditLog(u.cfg, AuditEntry{
		Action:    "UNBAN",
		IP:        ip,
		Condition: fmt.Sprintf("ban #%d expired", banCount),
		Duration:  nextDuration,
		Timestamp: time.Now(),
	})

	// ── 8. Send Slack notification ─────────────────────────────────────────
	// Runs in its own goroutine so a slow Slack response never blocks unbanning.
	go u.notifier.SendUnbanAlert(ip, nextDuration)

	fmt.Printf("[unbanner] %s unbanned. Next ban if reoffending: %s\n",
		ip, nextDuration)
}

// nextBanDuration returns a human-readable string showing what the
// next ban duration would be for an IP with the given ban history.
func (u *Unbanner) nextBanDuration(currentBanCount int) string {
	durations := u.cfg.Blocking.BanDurationsMinutes

	// The next ban uses the index equal to the current ban count
	// (since ban count was already incremented when the ban was applied).
	nextIdx := currentBanCount
	if nextIdx >= len(durations) {
		nextIdx = len(durations) - 1
	}

	next := durations[nextIdx]
	if next == -1 {
		return "permanent"
	}
	return fmt.Sprintf("%d minutes", next)
}
