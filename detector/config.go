package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level struct that mirrors the shape of config.yaml.
// Each field maps to a section in the YAML file.
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Slack     SlackConfig     `yaml:"slack"`
	Detection DetectionConfig `yaml:"detection"`
	Blocking  BlockingConfig  `yaml:"blocking"`
}

// ServerConfig holds values related to the daemon's own server settings.
type ServerConfig struct {
	DashboardPort int    `yaml:"dashboard_port"`
	LogPath       string `yaml:"log_path"`
	AuditLogPath  string `yaml:"audit_log_path"`
}

// SlackConfig holds the Slack webhook URL.
type SlackConfig struct {
	WebhookURL string `yaml:"webhook_url"`
}

// DetectionConfig holds all the thresholds used by the detection engine.
type DetectionConfig struct {
	SlidingWindowSeconds          int     `yaml:"sliding_window_seconds"`
	BaselineWindowMinutes         int     `yaml:"baseline_window_minutes"`
	BaselineRecalcIntervalSeconds int     `yaml:"baseline_recalc_interval_seconds"`
	ZScoreThreshold               float64 `yaml:"z_score_threshold"`
	RateMultiplierThreshold       float64 `yaml:"rate_multiplier_threshold"`
	ErrorSurgeMultiplier          float64 `yaml:"error_surge_multiplier"`
	MinRequestsForBaseline        int     `yaml:"min_requests_for_baseline"`
}

// BlockingConfig holds the ban duration ladder (in minutes).
// -1 means permanent ban.
type BlockingConfig struct {
	BanDurationsMinutes []int `yaml:"ban_durations_minutes"`
}

// LoadConfig reads the YAML file at the given path and returns a populated
// Config struct. It returns an error if the file can't be opened or parsed.
func LoadConfig(path string) (*Config, error) {
	// os.Open opens the file at the given path.
	// It returns two things: the file, and an error.
	// This is Go's pattern — functions return (result, error).
	file, err := os.Open(path)
	if err != nil {
		// If err is not nil, something went wrong. We wrap the error
		// with context so the caller knows what failed and why.
		return nil, fmt.Errorf("could not open config file: %w", err)
	}
	// defer means "run this when the function exits, no matter what".
	// This ensures the file is always closed — even if we return early.
	defer file.Close()

	// Create an empty Config struct to fill in.
	var cfg Config

	// yaml.NewDecoder reads from the file, .Decode fills our struct.
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("could not parse config file: %w", err)
	}

	// Return a pointer to the config, and nil for the error (nil = no error).
	return &cfg, nil
}
