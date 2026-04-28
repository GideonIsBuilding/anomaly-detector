package main

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Dashboard serves the live metrics web UI.
// It exposes two endpoints:
//
//	GET /         → the HTML page (auto-refreshes via JS)
//	GET /api/metrics → JSON data the page polls every 3 seconds
type Dashboard struct {
	cfg       *Config
	baseline  *Baseline
	detector  *Detector
	blocker   *Blocker
	startTime time.Time
}

// MetricsSnapshot is the JSON payload sent to the frontend every 3 seconds.
type MetricsSnapshot struct {
	Uptime          string    `json:"uptime"`
	GlobalReqPS     float64   `json:"global_req_ps"`
	CPUPercent      float64   `json:"cpu_percent"`
	MemoryMB        float64   `json:"memory_mb"`
	EffectiveMean   float64   `json:"effective_mean"`
	EffectiveStdDev float64   `json:"effective_stddev"`
	ActiveBans      int       `json:"active_bans"`
	BannedIPs       []BanInfo `json:"banned_ips"`
	TopIPs          []IPStat  `json:"top_ips"`
	Timestamp       string    `json:"timestamp"`
}

// BanInfo is a simplified view of a BanRecord for the frontend.
type BanInfo struct {
	IP          string `json:"ip"`
	BanCount    int    `json:"ban_count"`
	BannedAt    string `json:"banned_at"`
	ExpiresAt   string `json:"expires_at"`
	IsPermanent bool   `json:"is_permanent"`
}

// NewDashboard creates and returns a ready-to-use Dashboard.
func NewDashboard(cfg *Config, baseline *Baseline, detector *Detector, blocker *Blocker) *Dashboard {
	return &Dashboard{
		cfg:       cfg,
		baseline:  baseline,
		detector:  detector,
		blocker:   blocker,
		startTime: time.Now(),
	}
}

// Start launches the HTTP server. Designed to run as a goroutine.
func (d *Dashboard) Start() {
	mux := http.NewServeMux()

	// Route: HTML dashboard page.
	mux.HandleFunc("/", d.handleIndex)

	// Route: JSON metrics API — polled by the frontend every 3 seconds.
	mux.HandleFunc("/api/metrics", d.handleMetrics)

	addr := fmt.Sprintf(":%d", d.cfg.Server.DashboardPort)
	fmt.Printf("[dashboard] serving on http://0.0.0.0%s\n", addr)

	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Printf("[dashboard] server error: %v\n", err)
	}
}

// handleMetrics builds a MetricsSnapshot and writes it as JSON.
func (d *Dashboard) handleMetrics(w http.ResponseWriter, r *http.Request) {
	mean, stddev, _ := d.baseline.GetStats()

	// Build banned IP list.
	bans := d.blocker.GetBans()
	banInfos := make([]BanInfo, 0, len(bans))
	for _, b := range bans {
		expiresStr := "never"
		if !b.IsPermanent && !b.ExpiresAt.IsZero() {
			expiresStr = b.ExpiresAt.UTC().Format(time.RFC3339)
		}
		banInfos = append(banInfos, BanInfo{
			IP:          b.IP,
			BanCount:    b.BanCount,
			BannedAt:    b.BannedAt.UTC().Format(time.RFC3339),
			ExpiresAt:   expiresStr,
			IsPermanent: b.IsPermanent,
		})
	}

	snapshot := MetricsSnapshot{
		Uptime:          formatUptime(time.Since(d.startTime)),
		GlobalReqPS:     roundTo2(d.detector.GetGlobalRate()),
		CPUPercent:      roundTo2(getCPUPercent()),
		MemoryMB:        roundTo2(getMemoryMB()),
		EffectiveMean:   roundTo2(mean),
		EffectiveStdDev: roundTo2(stddev),
		ActiveBans:      d.blocker.GetActiveBanCount(),
		BannedIPs:       banInfos,
		TopIPs:          d.detector.GetTopIPs(10),
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	// Allow browser to poll from any origin — needed if dashboard
	// is on a subdomain different from the API.
	w.Header().Set("Access-Control-Allow-Origin", "*")

	if err := json.NewEncoder(w).Encode(snapshot); err != nil {
		http.Error(w, "failed to encode metrics", http.StatusInternalServerError)
	}
}

// handleIndex serves the HTML dashboard page.
func (d *Dashboard) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, dashboardHTML)
}

// ── system metrics helpers ─────────────────────────────────────────────────

// getMemoryMB returns the current process memory usage in megabytes.
// Uses Go's runtime package — no external dependencies needed.
func getMemoryMB() float64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// Alloc is bytes of allocated heap objects.
	return float64(m.Alloc) / 1024 / 1024
}

// getCPUPercent reads /proc/stat to estimate CPU usage over a short interval.
// This is Linux-specific — perfect for our VPS deployment.
func getCPUPercent() float64 {
	// Read /proc/stat twice with a 100ms gap and compare.
	s1, err := readCPUStat()
	if err != nil {
		return 0
	}
	time.Sleep(100 * time.Millisecond)
	s2, err := readCPUStat()
	if err != nil {
		return 0
	}

	// Calculate the delta between the two reads.
	totalDelta := float64(s2.total - s1.total)
	idleDelta := float64(s2.idle - s1.idle)

	if totalDelta == 0 {
		return 0
	}
	// CPU% = (1 - idle/total) * 100
	return (1 - idleDelta/totalDelta) * 100
}

// cpuStat holds the raw values from /proc/stat.
type cpuStat struct {
	total uint64
	idle  uint64
}

// readCPUStat reads the first line of /proc/stat and parses the CPU fields.
func readCPUStat() (cpuStat, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuStat{}, err
	}

	// First line looks like: cpu  264230 1876 66243 2696351 3346 0 3508 0 0 0
	// Fields: user nice system idle iowait irq softirq steal guest guest_nice
	line := strings.Split(string(data), "\n")[0]
	fields := strings.Fields(line)

	// fields[0] is "cpu", fields[1..] are the numbers.
	if len(fields) < 5 {
		return cpuStat{}, fmt.Errorf("unexpected /proc/stat format")
	}

	var values []uint64
	for _, f := range fields[1:] {
		v, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			continue
		}
		values = append(values, v)
	}

	if len(values) < 4 {
		return cpuStat{}, fmt.Errorf("not enough cpu fields")
	}

	var total uint64
	for _, v := range values {
		total += v
	}

	// idle is the 4th value (index 3).
	return cpuStat{total: total, idle: values[3]}, nil
}

// ── formatting helpers ─────────────────────────────────────────────────────

// formatUptime converts a duration into a human-readable string.
func formatUptime(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%02dh %02dm %02ds", h, m, s)
}

// roundTo2 rounds a float64 to 2 decimal places.
func roundTo2(v float64) float64 {
	return math.Round(v*100) / 100
}

// ── HTML template ──────────────────────────────────────────────────────────

// dashboardHTML is the complete single-page dashboard.
// It polls /api/metrics every 3 seconds and updates the UI without reload.
const dashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HNG Anomaly Detector — Live Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      background: #0d1117;
      color: #c9d1d9;
      font-family: 'Courier New', monospace;
      padding: 24px;
    }

    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid #30363d;
    }

    header h1 {
      color: #58a6ff;
      font-size: 1.4rem;
      letter-spacing: 0.05em;
    }

    #status-dot {
      width: 10px; height: 10px;
      border-radius: 50%;
      background: #3fb950;
      display: inline-block;
      margin-right: 8px;
      animation: pulse 2s infinite;
    }

    @keyframes pulse {
      0%, 100% { opacity: 1; }
      50%       { opacity: 0.4; }
    }

    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }

    .card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 20px;
    }

    .card .label {
      font-size: 0.75rem;
      color: #8b949e;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 8px;
    }

    .card .value {
      font-size: 1.8rem;
      font-weight: bold;
      color: #f0f6fc;
    }

    .card .value.danger { color: #f85149; }
    .card .value.warn   { color: #d29922; }
    .card .value.ok     { color: #3fb950; }

    .section {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 16px;
    }

    .section h2 {
      font-size: 0.85rem;
      color: #8b949e;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 16px;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
    }

    th {
      text-align: left;
      color: #8b949e;
      font-weight: normal;
      padding: 6px 12px;
      border-bottom: 1px solid #30363d;
    }

    td {
      padding: 8px 12px;
      border-bottom: 1px solid #21262d;
    }

    td.ip    { color: #58a6ff; font-weight: bold; }
    td.ban   { color: #f85149; }
    td.count { color: #d29922; }

    .empty {
      color: #8b949e;
      font-style: italic;
      font-size: 0.85rem;
      padding: 12px 0;
    }

    footer {
      margin-top: 24px;
      font-size: 0.75rem;
      color: #8b949e;
      text-align: center;
    }

    #last-update { color: #58a6ff; }
  </style>
</head>
<body>

<header>
  <h1><span id="status-dot"></span>HNG Anomaly Detector</h1>
  <div>Uptime: <strong id="uptime">--</strong></div>
</header>

<!-- Stat cards row -->
<div class="grid">
  <div class="card">
    <div class="label">Global Req/s</div>
    <div class="value" id="global-rps">--</div>
  </div>
  <div class="card">
    <div class="label">Active Bans</div>
    <div class="value" id="active-bans">--</div>
  </div>
  <div class="card">
    <div class="label">Baseline Mean</div>
    <div class="value" id="eff-mean">--</div>
  </div>
  <div class="card">
    <div class="label">Baseline StdDev</div>
    <div class="value" id="eff-stddev">--</div>
  </div>
  <div class="card">
    <div class="label">CPU Usage</div>
    <div class="value" id="cpu">--</div>
  </div>
  <div class="card">
    <div class="label">Memory</div>
    <div class="value" id="memory">--</div>
  </div>
</div>

<!-- Banned IPs table -->
<div class="section">
  <h2>🚫 Banned IPs</h2>
  <table id="ban-table">
    <thead>
      <tr>
        <th>IP Address</th>
        <th>Banned At</th>
        <th>Expires At</th>
        <th>Offences</th>
      </tr>
    </thead>
    <tbody id="ban-body">
      <tr><td colspan="4" class="empty">No active bans</td></tr>
    </tbody>
  </table>
</div>

<!-- Top IPs table -->
<div class="section">
  <h2>📊 Top 10 Source IPs (last 60s)</h2>
  <table>
    <thead>
      <tr>
        <th>IP Address</th>
        <th>Requests (window)</th>
      </tr>
    </thead>
    <tbody id="top-body">
      <tr><td colspan="2" class="empty">No traffic yet</td></tr>
    </tbody>
  </table>
</div>

<footer>
  Last updated: <span id="last-update">--</span> &nbsp;|&nbsp; Refreshes every 3 seconds
</footer>

<script>
  // Poll the metrics API every 3 seconds and update the DOM.
  async function fetchMetrics() {
    try {
      const res  = await fetch('/api/metrics');
      const data = await res.json();
      updateCards(data);
      updateBans(data.banned_ips);
      updateTopIPs(data.top_ips);
      document.getElementById('last-update').textContent = new Date().toLocaleTimeString();
    } catch (e) {
      console.error('metrics fetch failed', e);
    }
  }

  function updateCards(data) {
    document.getElementById('uptime').textContent     = data.uptime;
    document.getElementById('global-rps').textContent = data.global_req_ps + ' req/s';
    document.getElementById('eff-mean').textContent   = data.effective_mean + ' req/s';
    document.getElementById('eff-stddev').textContent = data.effective_stddev;
    document.getElementById('cpu').textContent        = data.cpu_percent + '%';
    document.getElementById('memory').textContent     = data.memory_mb + ' MB';

    // Colour the ban count red if there are active bans.
    const bansEl = document.getElementById('active-bans');
    bansEl.textContent = data.active_bans;
    bansEl.className = 'value ' + (data.active_bans > 0 ? 'danger' : 'ok');
  }

  function updateBans(bans) {
    const tbody = document.getElementById('ban-body');
    if (!bans || bans.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" class="empty">No active bans</td></tr>';
      return;
    }
    tbody.innerHTML = bans.map(function(b) {
      return '<tr>' +
        '<td class="ip">' + b.ip + '</td>' +
        '<td>' + b.banned_at + '</td>' +
        '<td class="ban">' + (b.is_permanent ? '⛔ PERMANENT' : b.expires_at) + '</td>' +
        '<td class="count">' + b.ban_count + '</td>' +
        '</tr>';
    }).join('');
  }

  function updateTopIPs(ips) {
    const tbody = document.getElementById('top-body');
    if (!ips || ips.length === 0) {
      tbody.innerHTML = '<tr><td colspan="2" class="empty">No traffic yet</td></tr>';
      return;
    }
    tbody.innerHTML = ips.map(function(ip) {
      return '<tr>' +
        '<td class="ip">' + ip.IP + '</td>' +
        '<td class="count">' + ip.Requests + '</td>' +
        '</tr>';
    }).join('');
  }

  // Fetch immediately on load, then every 3 seconds.
  fetchMetrics();
  setInterval(fetchMetrics, 3000);
</script>
</body>
</html>`
