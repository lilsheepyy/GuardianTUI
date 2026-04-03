package proxy

import (
	"os"
	"gopkg.in/yaml.v3"
)

type AIConfig struct {
	Endpoints       []string `yaml:"endpoints"`
	ProtectPII      bool     `yaml:"protect_pii"`
	BlockedKeywords []string `yaml:"blocked_keywords"`
	ScoreThreshold  int      `yaml:"score_threshold"`
}

type EngineConfig struct {
	Mode             string `yaml:"mode"` // ips, ids, strict
	MaxScanSize      int    `yaml:"max_scan_size_bytes"`
	ProbingWindow    int    `yaml:"probing_window_seconds"`
	ProbingThreshold int    `yaml:"probing_threshold_unique"`
	SpamThreshold    int    `yaml:"spam_threshold_total"`
	PoWEnabled       bool   `yaml:"pow_enabled"`
	PoWForce         bool   `yaml:"pow_force"`
	PoWDifficulty    int    `yaml:"pow_difficulty"`
}

type TUIConfig struct {
	Theme string `yaml:"theme"`
}

type Config struct {
	Whitelist         []string     `yaml:"whitelist"`
	BlockedUserAgents []string     `yaml:"blocked_user_agents"`
	HoneypotPaths     []string     `yaml:"honeypot_paths"`
	BlocklistPath     string       `yaml:"blocklist_path"`
	RemoteBlocklists  []string     `yaml:"remote_blocklists"`
	AIProtection      AIConfig     `yaml:"ai_protection"`
	Engine            EngineConfig `yaml:"engine"`
	TUI               TUIConfig    `yaml:"tui"`
	
	// Anonymous Telemetry (Heartbeat)
	TelemetryEnabled *bool `yaml:"telemetry_enabled,omitempty"`
	TelemetryAsked   bool  `yaml:"telemetry_asked,omitempty"`
}

func (c *Config) Save(path string) error {
	data, err := yaml.Marshal(c)
	if err != nil { return err }
	return os.WriteFile(path, data, 0644)
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Return default values if config doesn't exist
			return &Config{
				Engine: EngineConfig{
					MaxScanSize:      1024 * 1024,
					ProbingWindow:    60,
					ProbingThreshold: 3,
					SpamThreshold:    5,
				},
				AIProtection: AIConfig{
					ScoreThreshold: 5,
				},
			}, nil
		}
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	
	// Set defaults for missing values
	if cfg.Engine.Mode == "" { cfg.Engine.Mode = "ips" }
	if cfg.Engine.MaxScanSize == 0 { cfg.Engine.MaxScanSize = 1024 * 1024 }
	if cfg.Engine.ProbingWindow == 0 { cfg.Engine.ProbingWindow = 60 }
	if cfg.AIProtection.ScoreThreshold == 0 { cfg.AIProtection.ScoreThreshold = 5 }
	
	return &cfg, nil
}
