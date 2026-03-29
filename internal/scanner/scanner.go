package scanner

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

type ThreatLevel string

const (
	LevelLow      ThreatLevel = "LOW"
	LevelMedium   ThreatLevel = "MEDIUM"
	LevelHigh     ThreatLevel = "HIGH"
	LevelCritical ThreatLevel = "CRITICAL"
)

type Detection struct {
	Pattern string
	Level   ThreatLevel
	Type    string
}

// Advanced Regex Patterns (OWASP Top 10)
var patterns = []Detection{
	{Pattern: `(?i)(union(?:\s+all)?\s+select|select.*from|drop\s+table|insert\s+into|truncate\s+table|delete\s+from|waitfor\s+delay|1=1|' OR '1'='1|--|#)`, Level: LevelCritical, Type: "SQL Injection"},
	{Pattern: `(?i)(<script.*?>|javascript:|alert\s*\(|onerror\s*=|onclick\s*=|onload\s*=|document\.cookie)`, Level: LevelHigh, Type: "XSS Attempt"},
	{Pattern: `(?i)(\.\.\/|\.\.\\|/etc/passwd|/windows/win\.ini|/proc/self/environ|file://|php://filter)`, Level: LevelCritical, Type: "Path Traversal / LFI"},
	{Pattern: `(?i)(;\s*ls|\|\s*id|` + "`" + `id` + "`" + `|\$\(id\)|exec\s*\(|system\s*\(|passthru\s*\(|shell_exec\s*\(|eval\s*\()`, Level: LevelCritical, Type: "Command Injection / RCE"},
	{Pattern: `(?i)(\.env|wp-config\.php|id_rsa|\.aws/credentials|/.git/|docker-compose\.yml)`, Level: LevelCritical, Type: "Sensitive File Access"},
}

var maliciousAgents = []string{
	"sqlmap", "nmap", "nikto", "dirbuster", "masscan", "zgrab", "nuclei", "burpsuite",
	"acunetix", "nessus", "qualys", "openvas", "netsparker", "arachni", "w3af", "havij",
	"gobuster", "wfuzz", "ffuf", "dirsearch", "feroxbuster", "rustbuster", "dirb",
	"amass", "subfinder", "httpx", "dnsx", "gau", "waybackpack", "hakrawler",
	"shodan", "censys", "binaryedge", "mj12bot", "ahrefsbot", "semrushbot",
}

var scannerHeaders = []string{"X-Scanner", "X-Scanning-IP", "X-Scan-Type", "X-Bug-Bounty", "X-Scan-ID"}

// --- SHARDING IMPLEMENTATION ---
const ShardCount = 64

type Shard struct {
	mu      sync.Mutex
	tracker map[string][]time.Time
}

var shards [ShardCount]*Shard

func init() {
	for i := 0; i < ShardCount; i++ {
		shards[i] = &Shard{tracker: make(map[string][]time.Time)}
	}
}

func getShard(ip string) *Shard {
	var hash uint32
	for i := 0; i < len(ip); i++ {
		hash = 31*hash + uint32(ip[i])
	}
	return shards[hash%ShardCount]
}

const (
	RateLimitWindow   = 10 * time.Second
	MaxRequestsPerWin = 100 // Optimized threshold
)

func CheckRateLimit(ip string) *Detection {
	shard := getShard(ip)
	shard.mu.Lock()
	defer shard.mu.Unlock()

	now := time.Now()
	recent := []time.Time{}

	for _, t := range shard.tracker[ip] {
		if now.Sub(t) < RateLimitWindow {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	shard.tracker[ip] = recent

	if len(recent) > MaxRequestsPerWin {
		return &Detection{Pattern: "High Rate", Level: LevelHigh, Type: "DoS / Brute Force"}
	}
	return nil
}

// --- SCANNING LOGIC ---

func Scan(input string, ip string, rHeaders map[string][]string, userAgent string) *Detection {
	// 1. Rate Limit (Sharded)
	if d := CheckRateLimit(ip); d != nil {
		return d
	}

	// 2. User Agent
	uaLower := strings.ToLower(userAgent)
	for _, agent := range maliciousAgents {
		if strings.Contains(uaLower, agent) {
			return &Detection{Pattern: agent, Level: LevelHigh, Type: "Malicious Scanner / Bot"}
		}
	}

	// 3. Headers
	for _, h := range scannerHeaders {
		if _, ok := rHeaders[h]; ok {
			return &Detection{Pattern: h, Level: LevelMedium, Type: "Scanner Header"}
		}
	}

	// 4. Cookies Scanning
	if cookieHeader, ok := rHeaders["Cookie"]; ok {
		for _, c := range cookieHeader {
			if d := matchPatterns(c); d != nil {
				d.Type = "Cookie Threat: " + d.Type
				return d
			}
		}
	}

	// 5. Payload Patterns
	return matchPatterns(input)
}

func matchPatterns(input string) *Detection {
	for _, d := range patterns {
		re := regexp.MustCompile(d.Pattern)
		if re.MatchString(input) {
			return &d
		}
	}
	if len(input) > 12000 {
		return &Detection{Pattern: "Oversized", Level: LevelMedium, Type: "Payload Anomaly"}
	}
	return nil
}
