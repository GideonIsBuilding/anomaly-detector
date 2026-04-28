package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// LogEntry represents one parsed line from the Nginx JSON access log.
// The json:"..." tags map each field to its key in the JSON log line.
type LogEntry struct {
	SourceIP     string `json:"source_ip"`
	Timestamp    string `json:"timestamp"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	Status       int    `json:"status"`
	ResponseSize int    `json:"response_size"`
}

// Monitor is responsible for tailing the log file and sending
// parsed entries into a channel for the detector to consume.
type Monitor struct {
	cfg *Config
}

// NewMonitor creates and returns a new Monitor.
// This is the Go convention for constructing a struct — a "constructor function".
func NewMonitor(cfg *Config) *Monitor {
	return &Monitor{cfg: cfg}
}

// Start begins tailing the log file. It runs forever (until the program exits).
// It sends every successfully parsed LogEntry into the provided channel.
// This function is designed to be launched as a goroutine: go monitor.Start(ch)
func (m *Monitor) Start(entries chan<- LogEntry) {
	// We loop forever here because if the file isn't ready yet,
	// we want to keep retrying rather than crashing the whole daemon.
	for {
		err := m.tailFile(entries)
		if err != nil {
			// Log the error and wait before retrying.
			// This handles the case where Nginx hasn't created the log file yet.
			fmt.Printf("[monitor] error tailing file: %v — retrying in 5s\n", err)
			time.Sleep(5 * time.Second)
		}
	}
}

// tailFile opens the log file and reads it line by line, forever.
// When it reaches the end of the file, it waits and tries again (like tail -f).
func (m *Monitor) tailFile(entries chan<- LogEntry) error {
	// Open the log file in read-only mode.
	file, err := os.Open(m.cfg.Server.LogPath)
	if err != nil {
		return fmt.Errorf("could not open log file: %w", err)
	}
	defer file.Close()

	// Seek to the END of the file on startup.
	// We don't want to re-process old log lines when the daemon starts.
	_, err = file.Seek(0, io.SeekEnd)
	if err != nil {
		return fmt.Errorf("could not seek to end of file: %w", err)
	}

	// bufio.NewReader wraps the file with a buffer for efficient line reading.
	reader := bufio.NewReader(file)

	fmt.Println("[monitor] started tailing", m.cfg.Server.LogPath)

	// This loop runs forever — reading one line at a time.
	for {
		// ReadString reads until it hits a newline character '\n'.
		line, err := reader.ReadString('\n')

		if err != nil {
			// io.EOF means we've hit the end of the file — no new lines yet.
			// This is NOT a real error — it just means we need to wait.
			if err == io.EOF {
				time.Sleep(100 * time.Millisecond)
				continue // go back to the top of the loop and try again
			}
			// Any other error IS a real problem — return it.
			return fmt.Errorf("error reading log line: %w", err)
		}

		// Try to parse the line as a JSON LogEntry.
		var entry LogEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			// Skip malformed lines — Nginx sometimes writes partial lines.
			continue
		}

		// Send the parsed entry into the channel.
		// The arrow points in the direction data flows: into the channel.
		entries <- entry
	}
}
