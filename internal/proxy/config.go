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
	MaxScanSize      int `yaml:"max_scan_size_bytes"`
	ProbingWindow    int `yaml:"probing_window_seconds"`
	ProbingThreshold int `yaml:"probing_threshold_unique"`
	SpamThreshold    int `yaml:"spam_threshold_total"`
}

type Config struct {
	Whitelist         []string     `yaml:"whitelist"`
	BlockedUserAgents []string     `yaml:"blocked_user_agents"`
	BlocklistPath     string       `yaml:"blocklist_path"`
	AIProtection      AIConfig     `yaml:"ai_protection"`
	Engine            EngineConfig `yaml:"engine"`
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
	if cfg.Engine.MaxScanSize == 0 { cfg.Engine.MaxScanSize = 1024 * 1024 }
	if cfg.Engine.ProbingWindow == 0 { cfg.Engine.ProbingWindow = 60 }
	if cfg.AIProtection.ScoreThreshold == 0 { cfg.AIProtection.ScoreThreshold = 5 }
	
	return &cfg, nil
}
