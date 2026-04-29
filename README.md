# Anomaly Detector

A real-time HTTP traffic anomaly detection and DDoS mitigation engine built for cloud.ng; a Nextcloud-powered cloud storage platform. The detector runs as a daemon alongside Nextcloud, learns what normal traffic looks like, and automatically blocks aggressive IPs via `iptables` when something deviates.

---

## Live Links

| Resource | URL |
|---|---|
| Metrics Dashboard | `http://detector.gideonisbuilding.tech/` |
| Nextcloud (IP only) | `http://http://100.49.26.66/` |
| GitHub Repository | `https://github.com/GideonIsBuilding/anomaly-detector` |

> **Note:** Both links are live during the grading window.

---

## Language Choice

This project is written in **Go**.

Go was chosen for this project for the following reasons:

- **Concurrency model** — goroutines and channels make it natural to run the log tailer, baseline engine, detector, blocker, unbanner, and dashboard all in parallel without complex threading code.
- **Performance** — Go compiles to a single static binary with minimal memory overhead, ideal for a daemon that must run continuously for 12+ hours.
- **Standard library** — `net/http`, `os/exec`, `bufio`, `encoding/json`, and `sync` cover everything this project needs without pulling in heavy frameworks.
- **No runtime dependencies** — the compiled binary runs on any Linux VPS with no Go installation required.

---

## Architecture

```
[Nginx] ──writes──▶ /var/log/nginx/hng-access.log (shared Docker volume)
                              │
                              ▼
                       [Monitor goroutine]
                       tails log line by line
                              │
                         channel: LogEntry
                              │
                              ▼
                       [Detector goroutine]
                       sliding window + z-score
                              │
                         channel: AnomalyEvent
                              │
                 ┌────────────┴────────────┐
                 ▼                         ▼
          IP Anomaly                Global Anomaly
          [Blocker]                 Slack alert only
          iptables DROP
          Slack ban alert
                 │
                 ▼
          [Unbanner]
          timer fires after
          10min/30min/2hr/permanent
          removes iptables rule
          Slack unban alert
                 │
          [Dashboard goroutine]
          serves metrics at :8080
          refreshes every 3 seconds
```

---

## How the Sliding Window Works

The detector maintains two deque-based windows — one per IP, one global — tracking request timestamps over the last 60 seconds.

**Structure:** Each window is a Go slice of `time.Time` values. Every incoming request appends the current timestamp to the right side of the slice.

**Eviction logic:** On every new request, we walk the left side of the slice and drop any timestamps older than 60 seconds:

```go
for len(window) > 0 && now.Sub(window[0]) > windowDuration {
    window = window[1:]  // evict from the front
}
```

This means the slice always contains only the timestamps that fall within the current 60-second window. The length of the slice at any point in time is the raw request count. Dividing by 60 gives requests per second.

Two windows run in parallel:
- `ipWindows` — a `map[string][]time.Time` keyed by source IP
- `globalWindow` — a single `[]time.Time` across all IPs

A separate error window tracks 4xx/5xx timestamps per IP for error surge detection.

---

## How the Baseline Works

The baseline engine learns normal traffic by maintaining a rolling window of per-second request counts over the last **30 minutes**.

**Window size:** 30 minutes (1,800 one-second buckets maximum).

**Recalculation interval:** Every 60 seconds, `Recalculate()` runs and:
1. Evicts buckets older than 30 minutes from the window
2. Computes mean and standard deviation across all remaining buckets
3. Updates the per-hour slot for the current hour (0–23)
4. Selects the effective baseline — prefers the current hour's stats when it has enough data, falls back to the full 30-minute window otherwise

**Floor values:** The baseline initialises with `mean=1.0` and `stddev=1.0` so detection never fires against a zero baseline during cold start.

**Per-hour slots:** Traffic patterns differ between 2am and 2pm. Keeping one slot per hour means the baseline reflects the actual pattern for the time of day, not a blended average across very different traffic periods.

**Minimum samples:** The baseline requires at least 10 data points before it is considered valid. Below this threshold the floor values are used and a log line is emitted.

---

## Detection Logic

An IP or global rate is flagged as anomalous if **either** condition fires first:

**Z-score check:**
```
z = (current_rate - baseline_mean) / baseline_stddev
```
If `z > 3.0` the rate is more than 3 standard deviations above normal — statistically, this happens by chance less than 0.3% of the time under normal conditions.

**Rate multiplier check:**
```
rate > baseline_mean × 5.0
```
A simple absolute check that catches spikes even when the standard deviation is very small (e.g. during quiet periods where stddev ≈ 0).

**Error surge tightening:** If an IP's 4xx/5xx rate is ≥ 3× the baseline error mean, both thresholds are tightened by 30% for that IP — making detection more aggressive for misbehaving clients.

The detector emits one `AnomalyEvent` per IP per ban cycle. Once an IP is flagged, its alert flag is set and no further events fire until the unbanner clears it.

---

## How iptables Blocks an IP

When an IP anomaly is detected, the blocker runs:

```bash
iptables -A INPUT -s <IP> -j DROP
```

This adds a rule to the kernel's netfilter INPUT chain that silently drops all packets from the offending IP before they reach Nginx or any other process. The rule applies at the host network level — which is why the detector container runs with `network_mode: host` and the `NET_ADMIN` capability.

When an IP is unbanned, the rule is removed with:

```bash
iptables -D INPUT -s <IP> -j DROP
```

The blocker checks for duplicate rules before adding (`iptables -C`) to avoid stacking multiple DROP rules for the same IP.

**Ban backoff schedule:**

| Offence | Duration |
|---|---|
| 1st | 10 minutes |
| 2nd | 30 minutes |
| 3rd | 2 hours |
| 4th+ | Permanent |

---

## Repository Structure

```
anomaly-detector/
├── docker-compose.yml
├── nginx/
│   └── nginx.conf          # Reverse proxy + JSON access log config
├── detector/
│   ├── main.go             # Entry point — wires all goroutines together
│   ├── monitor.go          # Tails Nginx log, parses JSON lines
│   ├── baseline.go         # Rolling 30-min baseline, per-hour slots
│   ├── detector.go         # Sliding window, z-score, anomaly events
│   ├── blocker.go          # iptables rules, ban state, audit log
│   ├── unbanner.go         # Backoff timers, releases bans
│   ├── notifier.go         # Slack webhook alerts
│   ├── dashboard.go        # Live metrics web UI (net/http)
│   ├── config.go           # YAML config loader
│   ├── config.yaml         # All thresholds and settings
│   ├── Dockerfile
│   ├── go.mod
│   └── go.sum
├── docs/
│   └── architecture.png
├── screenshots/
│   ├── Tool-running.png
│   ├── Ban-slack.png
│   ├── Unban-slack.png
│   ├── Global-alert-slack.png
│   ├── Iptables-banned.png
│   ├── Audit-log.png
│   └── Baseline-graph.png
└── README.md
```

---

## Setup Instructions — Fresh VPS to Fully Running Stack

### Prerequisites

- Ubuntu 22.04 LTS VPS (minimum 2 vCPU, 2 GB RAM)
- A domain or subdomain pointed at your server IP (for the dashboard)
- A Slack incoming webhook URL

### Step 1 — Connect to your VPS

```bash
ssh root@YOUR_SERVER_IP
```

### Step 2 — Install Docker and Docker Compose

```bash
apt update && apt upgrade -y
apt install -y ca-certificates curl gnupg

install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | tee /etc/apt/sources.list.d/docker.list > /dev/null

apt update
apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
```

Verify:
```bash
docker --version
docker compose version
```

### Step 3 — Clone the Repository

```bash
git clone https://github.com/GideonIsBuilding/anomaly-detector.git
cd anomaly-detector
```

### Step 4 — Configure the Detector

Open `detector/config.yaml` and update:

```yaml
slack:
  webhook_url: "https://hooks.slack.com/services/YOUR/REAL/WEBHOOK"
```

All other thresholds are production-ready as-is.

### Step 5 — Set Up the Dashboard Domain

Point your subdomain DNS A record at your server IP, then add an Nginx server block on the host (outside Docker) to proxy the dashboard port:

```nginx
server {
    listen 80;
    server_name dashboard.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Step 6 — Build and Start the Stack

```bash
docker compose up -d --build
```

Verify all three containers are running:
```bash
docker compose ps
```

Expected output:
```
NAME         STATUS
nextcloud    running
nginx        running
detector     running
```

### Step 7 — Verify the Stack is Working

```bash
# Watch the detector logs live
docker compose logs -f detector

# Check iptables (should be empty at start)
sudo iptables -L -n

# Check the audit log
cat detector/audit/audit.log

# Hit the dashboard
curl http://SERVER_IP:8080/api/metrics
```

---

## Configuration Reference

All values live in `detector/config.yaml`. Nothing is hardcoded.

```yaml
server:
  dashboard_port: 8080
  log_path: /var/log/nginx/hng-access.log
  audit_log_path: /var/log/detector/audit.log

slack:
  webhook_url: "https://hooks.slack.com/services/..."

detection:
  sliding_window_seconds: 60          # deque window size
  baseline_window_minutes: 30         # rolling baseline history
  baseline_recalc_interval_seconds: 60
  z_score_threshold: 3.0              # stddevs above mean to trigger
  rate_multiplier_threshold: 5.0      # x above mean to trigger
  error_surge_multiplier: 3.0         # x baseline error rate to tighten
  min_requests_for_baseline: 10       # minimum samples before baseline is valid

blocking:
  ban_durations_minutes:
    - 10      # 1st offence
    - 30      # 2nd offence
    - 120     # 3rd offence
    - -1      # 4th+ offence (permanent)
```

---

## Audit Log Format

Every ban, unban, and baseline recalculation is written to the audit log:

```
[2024-01-01T12:00:00Z] BAN 1.2.3.4 | z-score=4.21 exceeds threshold=3.0 | rate=45.20 | baseline=8.10 | duration=10 minutes
[2024-01-01T12:10:00Z] UNBAN 1.2.3.4 | ban #1 expired | rate=0.00 | baseline=8.10 | duration=30 minutes
[2024-01-01T12:01:00Z] BASELINE_RECALC  | window=287 samples | rate=8.10 | baseline=8.10 | duration=
```

---

## Blog Post

A beginner-friendly walkthrough of how this project was built is published at:

> `https://medium.com/@gideonisbuilding/i-built-a-tool-that-detects-ddos-attacks-in-real-time-heres-exactly-how-it-works-95860a781468`

---

## Screenshots

| Screenshot | Description |
|---|---|
| `Tool-running.png` | Daemon running, processing log lines |
| `Ban-slack.png` | Slack ban notification |
| `Unban-slack.png` | Slack unban notification |
| `Global-alert-slack.png` | Slack global anomaly notification |
| `Iptables-banned.png` | `sudo iptables -L -n` showing a blocked IP |
| `Audit-log.png` | Structured audit log with events |
| `Baseline-graph.png` | Baseline over time with two hourly slots |

---

## Author

**Gideon**
DevOps & SRE Engineer — [linkedin.com](https://linkedin.com/in/gideon-aleonogwe) · [gideonisbuilding](https://gideonisbuilding.tech)