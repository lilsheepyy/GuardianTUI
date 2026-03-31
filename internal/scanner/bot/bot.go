package bot

import (
	"sync"
	"time"

	"guardiantui/internal/scanner/models"
)

const ShardCount = 64

type DetectionHistory struct {
	Type      string
	Timestamp time.Time
}

type Shard struct {
	mu      sync.Mutex
	history map[string][]DetectionHistory
}

var shards [ShardCount]*Shard

func init() {
	for i := 0; i < ShardCount; i++ {
		shards[i] = &Shard{history: make(map[string][]DetectionHistory)}
	}
}

func getShard(ip string) *Shard {
	var hash uint32
	for i := 0; i < len(ip); i++ { hash = 31*hash + uint32(ip[i]) }
	return shards[hash%ShardCount]
}

// CheckProbingBot tracks attacking behavior over time to detect distributed scanning or brute force probing.
func CheckProbingBot(ip string, newType string, windowSec, probThreshold, spamThreshold int) *models.Detection {
	shard := getShard(ip)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	
	now := time.Now()
	shard.history[ip] = append(shard.history[ip], DetectionHistory{Type: newType, Timestamp: now})
	
	uniqueTypes := make(map[string]bool)
	var updatedHistory []DetectionHistory
	window := time.Duration(windowSec) * time.Second
	
	for _, h := range shard.history[ip] {
		if now.Sub(h.Timestamp) < window {
			updatedHistory = append(updatedHistory, h)
			uniqueTypes[h.Type] = true
		}
	}
	shard.history[ip] = updatedHistory
	
	if len(uniqueTypes) >= probThreshold && probThreshold > 0 {
		return &models.Detection{
			Pattern: "Diverse Vuln Testing", 
			Level:   models.LevelCritical, 
			Type:    "Vulnerability Probing Bot (Diverse)",
		}
	}
	if len(updatedHistory) >= spamThreshold && spamThreshold > 0 {
		return &models.Detection{
			Pattern: "High Frequency Probing", 
			Level:   models.LevelCritical, 
			Type:    "Vulnerability Probing Bot (Spam)",
		}
	}
	return nil
}
