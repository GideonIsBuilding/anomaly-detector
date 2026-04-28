package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Notifier handles all outbound Slack alerts.
// Every alert type has its own method so the messages are consistent.
type Notifier struct {
	cfg        *Config
	httpClient *http.Client
}

// NewNotifier creates and returns a ready-to-use Notifier.
func NewNotifier(cfg *Config) *Notifier {
	return &Notifier{
		cfg: cfg,
		// Use a client with a timeout so a slow Slack never hangs the daemon.
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// slackPayload is the JSON structure Slack expects.
// "text" is the main message body.
// "attachments" let us add coloured sidebar blocks for extra detail.
type slackPayload struct {
	Text        string            `json:"text"`
	Attachments []slackAttachment `json:"attachments"`
}

type slackAttachment struct {
	Color  string       `json:"color"` // "danger" = red, "warning" = yellow, "good" = green
	Fields []slackField `json:"fields"`
}

type slackField struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"` // short=true means two fields sit side by side
}

// SendBanAlert fires when an IP is banned.
// Must arrive within 10 seconds of the ban — we use a short HTTP timeout above.
func (n *Notifier) SendBanAlert(event AnomalyEvent, duration string) {
	payload := slackPayload{
		Text: fmt.Sprintf(":rotating_light: *IP BANNED* — `%s`", event.IP),
		Attachments: []slackAttachment{
			{
				Color: "danger", // red sidebar
				Fields: []slackField{
					{Title: "Condition", Value: event.Condition, Short: false},
					{Title: "Current Rate", Value: fmt.Sprintf("%.2f req/s", event.CurrentRate), Short: true},
					{Title: "Baseline Mean", Value: fmt.Sprintf("%.2f req/s", event.Baseline), Short: true},
					{Title: "Z-Score", Value: fmt.Sprintf("%.2f", event.ZScore), Short: true},
					{Title: "Ban Duration", Value: duration, Short: true},
					{Title: "Detected At", Value: event.DetectedAt.UTC().Format(time.RFC3339), Short: false},
				},
			},
		},
	}

	if err := n.send(payload); err != nil {
		fmt.Printf("[notifier] failed to send ban alert for %s: %v\n", event.IP, err)
	} else {
		fmt.Printf("[notifier] ban alert sent for %s\n", event.IP)
	}
}

// SendUnbanAlert fires every time an IP is released from a ban.
func (n *Notifier) SendUnbanAlert(ip, nextBanDuration string) {
	payload := slackPayload{
		Text: fmt.Sprintf(":white_check_mark: *IP UNBANNED* — `%s`", ip),
		Attachments: []slackAttachment{
			{
				Color: "good", // green sidebar
				Fields: []slackField{
					{Title: "IP Address", Value: ip, Short: true},
					{Title: "Unbanned At", Value: time.Now().UTC().Format(time.RFC3339), Short: true},
					{Title: "Next Ban Duration (if reoffending)", Value: nextBanDuration, Short: false},
				},
			},
		},
	}

	if err := n.send(payload); err != nil {
		fmt.Printf("[notifier] failed to send unban alert for %s: %v\n", ip, err)
	} else {
		fmt.Printf("[notifier] unban alert sent for %s\n", ip)
	}
}

// SendGlobalAlert fires when a global traffic spike is detected.
// No IP is banned — this is informational only.
func (n *Notifier) SendGlobalAlert(event AnomalyEvent) {
	payload := slackPayload{
		Text: ":warning: *GLOBAL TRAFFIC ANOMALY DETECTED*",
		Attachments: []slackAttachment{
			{
				Color: "warning", // yellow sidebar
				Fields: []slackField{
					{Title: "Condition", Value: event.Condition, Short: false},
					{Title: "Global Rate", Value: fmt.Sprintf("%.2f req/s", event.CurrentRate), Short: true},
					{Title: "Baseline Mean", Value: fmt.Sprintf("%.2f req/s", event.Baseline), Short: true},
					{Title: "Z-Score", Value: fmt.Sprintf("%.2f", event.ZScore), Short: true},
					{Title: "Detected At", Value: event.DetectedAt.UTC().Format(time.RFC3339), Short: true},
				},
			},
		},
	}

	if err := n.send(payload); err != nil {
		fmt.Printf("[notifier] failed to send global alert: %v\n", err)
	} else {
		fmt.Println("[notifier] global alert sent")
	}
}

// send marshals the payload to JSON and POSTs it to the Slack webhook URL.
// This is the single place all HTTP communication happens.
func (n *Notifier) send(payload slackPayload) error {
	// Check if webhook is configured — skip silently if not.
	if n.cfg.Slack.WebhookURL == "" || n.cfg.Slack.WebhookURL == "https://hooks.slack.com/services/YOUR/WEBHOOK/URL" {
		fmt.Println("[notifier] no Slack webhook configured — skipping alert")
		return nil
	}

	// Marshal the payload struct into a JSON byte slice.
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("could not marshal slack payload: %w", err)
	}

	// bytes.NewReader wraps the byte slice so http.Post can read it.
	req, err := http.NewRequest(http.MethodPost, n.cfg.Slack.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("could not build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Execute the request using our client (which has a timeout set).
	resp, err := n.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("slack POST failed: %w", err)
	}
	defer resp.Body.Close()

	// Slack returns "ok" as the body on success.
	// Any non-200 status is a problem worth logging.
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack returned non-200 status: %d", resp.StatusCode)
	}

	return nil
}
