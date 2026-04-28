package main

import (
	"fmt"
	"log"
	"time"
)

func main() {
	// ── 1. Load config ─────────────────────────────────────────────────────
	cfg, err := LoadConfig("config.yaml")
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	fmt.Println("[main] config loaded")

	// ── 2. Create channels ─────────────────────────────────────────────────
	// entries carries parsed log lines from monitor → detector.
	// anomalies carries detected events from detector → blocker.
	entries := make(chan LogEntry, 100)
	anomalies := make(chan AnomalyEvent, 50)

	// ── 3. Build all components ────────────────────────────────────────────
	monitor := NewMonitor(cfg)
	baseline := NewBaseline(cfg)
	detector := NewDetector(cfg, baseline)
	notifier := NewNotifier(cfg)
	blocker := NewBlocker(cfg, notifier)
	unbanner := NewUnbanner(cfg, blocker, detector, notifier)
	dashboard := NewDashboard(cfg, baseline, detector, blocker)

	// Inject unbanner into blocker — breaks the circular dependency.
	blocker.SetUnbanner(unbanner)

	// ── 4. Launch all goroutines ───────────────────────────────────────────

	// Monitor: tails the Nginx log → sends LogEntry into entries channel.
	go monitor.Start(entries)

	// Baseline recalculation: fires every 60 seconds.
	go func() {
		ticker := time.NewTicker(
			time.Duration(cfg.Detection.BaselineRecalcIntervalSeconds) * time.Second,
		)
		for range ticker.C {
			baseline.Recalculate()
		}
	}()

	// Detector: reads entries → sends AnomalyEvent into anomalies channel.
	go detector.Start(entries, anomalies)

	// Blocker: reads anomalies → bans IPs, sends Slack alerts.
	go blocker.Start(anomalies)

	// Dashboard: serves the live metrics web UI.
	go dashboard.Start()

	// ── 5. Print startup summary ───────────────────────────────────────────
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("  HNG Anomaly Detector — RUNNING")
	fmt.Printf("  Log file:   %s\n", cfg.Server.LogPath)
	fmt.Printf("  Audit log:  %s\n", cfg.Server.AuditLogPath)
	fmt.Printf("  Dashboard:  http://0.0.0.0:%d\n", cfg.Server.DashboardPort)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// ── 6. Block main goroutine forever ───────────────────────────────────
	// All work happens in goroutines above.
	// select{} with no cases blocks without consuming CPU.
	select {}
}
