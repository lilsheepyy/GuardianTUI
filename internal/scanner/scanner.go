package scanner

import (
	"encoding/base64"
	"encoding/hex"
	"html"
	"net/url"
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

var patterns = []Detection{
	{Pattern: `(?i)(union(?:\s+all)?\s+select|select.*from|drop\s+table|insert\s+into|truncate\s+table|delete\s+from|waitfor\s+delay|1=1|' OR '1'='1|--|#|' OR 'x'='x|"\s+or\s+"x"="x|admin'\s+--|admin'\s+#|' OR TRUE--|"\s+OR\s+TRUE--)`, Level: LevelCritical, Type: "SQL Injection"},
	{Pattern: `(?i)(<script.*?>|javascript:|alert\s*\(|onerror\s*=|onclick\s*=|onload\s*=|document\.cookie|<img\s+src=.*onerror=|<svg/onload=)`, Level: LevelHigh, Type: "XSS Attempt"},
	{Pattern: `(?i)(\.\.\/|\.\.\\|/etc/passwd|/windows/win\.ini|/proc/self/environ|file://|php://filter|expect://|zip://|data://)`, Level: LevelCritical, Type: "Path Traversal / LFI"},
	{Pattern: `(?i)(;\s*ls|\|\s*id|` + "`" + `id` + "`" + `|\$\(id\)|exec\s*\(|system\s*\(|passthru\s*\(|shell_exec\s*\(|eval\s*\(|cat\s+/etc/|cat\${IFS}/etc/|uname\s+-a|/bin/sh|/bin/bash)`, Level: LevelCritical, Type: "Command Injection / RCE"},
	{Pattern: `(?i)(\.env|wp-config\.php|id_rsa|\.aws/credentials|/.git/|docker-compose\.yml|config\.json|web\.config|phpinfo\(\))`, Level: LevelCritical, Type: "Sensitive File Access"},
	{Pattern: `(?i)(\$gt|\$ne|\$in|\$where|\$regex|\$expr|\$exists|\$and|\$or|\$not)`, Level: LevelHigh, Type: "NoSQL Injection"},
	{Pattern: `(?i)({{\s*.*?\s*}}|\${\s*.*?\s*}|<%\s*.*?\s*%>|{{7\*7}}|{{config\.items\(\)}})`, Level: LevelHigh, Type: "SSTI Attempt"},
}

var maliciousAgents = []string{
	"sqlmap", "nmap", "nikto", "dirbuster", "masscan", "zgrab", "nuclei", "burpsuite",
	"acunetix", "nessus", "qualys", "openvas", "netsparker", "arachni", "w3af", "havij",
	"gobuster", "wfuzz", "ffuf", "dirsearch", "feroxbuster", "rustbuster", "dirb",
	"amass", "subfinder", "httpx", "dnsx", "gau", "waybackpack", "hakrawler",
	"shodan", "censys", "binaryedge", "mj12bot", "ahrefsbot", "semrushbot",
	"python-requests", "go-http-client", "curl", "wget", "libwww-perl", "php-http-client",
}

var scannerHeaders = []string{"X-Scanner", "X-Scanning-IP", "X-Scan-Type", "X-Bug-Bounty", "X-Scan-ID"}

// --- SHARDING IMPLEMENTATION ---
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
var compiledPatterns []*regexp.Regexp

func init() {
	for i := 0; i < ShardCount; i++ {
		shards[i] = &Shard{history: make(map[string][]DetectionHistory)}
	}
	for _, p := range patterns {
		compiledPatterns = append(compiledPatterns, regexp.MustCompile(p.Pattern))
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
	ProbingWindow    = 1 * time.Minute
	ProbingThreshold = 3
	SpamThreshold    = 5
)

func CheckProbingBot(ip string, newType string) *Detection {
	shard := getShard(ip)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	now := time.Now()
	shard.history[ip] = append(shard.history[ip], DetectionHistory{Type: newType, Timestamp: now})
	uniqueTypes := make(map[string]bool)
	var updatedHistory []DetectionHistory
	for _, h := range shard.history[ip] {
		if now.Sub(h.Timestamp) < ProbingWindow {
			updatedHistory = append(updatedHistory, h)
			uniqueTypes[h.Type] = true
		}
	}
	shard.history[ip] = updatedHistory
	if len(uniqueTypes) >= ProbingThreshold {
		return &Detection{Pattern: "Diverse Vuln Testing", Level: LevelCritical, Type: "Vulnerability Probing Bot (Diverse)"}
	}
	if len(updatedHistory) >= SpamThreshold {
		return &Detection{Pattern: "High Frequency Probing", Level: LevelCritical, Type: "Vulnerability Probing Bot (Spam)"}
	}
	return nil
}

// --- NORMALIZATION ENGINE ---

func normalize(input string) string {
	if input == "" { return "" }
	
	current := input
	for i := 0; i < 3; i++ { // Try up to 3 layers of decoding
		prev := current
		
		// 1. URL Decode
		if decoded, err := url.QueryUnescape(current); err == nil {
			current = decoded
		}
		
		// 2. HTML Entity Decode
		current = html.UnescapeString(current)
		
		// 3. Base64 Decode (if it looks like base64 and is long enough)
		if len(current) > 8 && !strings.Contains(current, " ") {
			if decoded, err := base64.StdEncoding.DecodeString(current); err == nil {
				current = string(decoded)
			}
		}

		// 4. Hex Decode (common in exploits)
		if strings.Contains(current, "\\x") {
			hexPattern := regexp.MustCompile(`\\x([0-9a-fA-F]{2})`)
			current = hexPattern.ReplaceAllStringFunc(current, func(s string) string {
				b, _ := hex.DecodeString(s[2:])
				return string(b)
			})
		}

		if prev == current { break }
	}
	return current
}

// --- SCANNING LOGIC ---

type ScanParams struct {
	Method    string
	Path      string
	Query     string
	Body      string
	Headers   map[string][]string
	IP        string
	UserAgent string
}

func Scan(params ScanParams) *Detection {
	var d *Detection

	// 1. User Agent
	ua := normalize(params.UserAgent)
	uaLower := strings.ToLower(ua)
	for _, agent := range maliciousAgents {
		if strings.Contains(uaLower, agent) {
			d = &Detection{Pattern: agent, Level: LevelHigh, Type: "Bot: Malicious Scanner"}
			break
		}
	}
	if d == nil {
		if d = matchPatterns(ua); d != nil {
			d.Type = "UA Attack: " + d.Type
		}
	}

	// 2. Headers
	if d == nil {
		for key, values := range params.Headers {
			normKey := normalize(key)
			if d = matchPatterns(normKey); d != nil {
				d.Type = "Header Key Attack: " + d.Type
				break
			}
			for _, sh := range scannerHeaders {
				if strings.EqualFold(normKey, sh) {
					d = &Detection{Pattern: key, Level: LevelMedium, Type: "Scanner Header Detected"}
					break
				}
			}
			if d != nil { break }
			for _, val := range values {
				normVal := normalize(val)
				if d = matchPatterns(normVal); d != nil {
					d.Type = "Header Value Attack: " + d.Type
					break
				}
			}
			if d != nil { break }
		}
	}

	// 3. URL Components
	if d == nil {
		if d = matchPatterns(normalize(params.Path)); d != nil {
			d.Type = "Path Attack: " + d.Type
		}
	}
	if d == nil {
		if d = matchPatterns(normalize(params.Query)); d != nil {
			d.Type = "Query Attack: " + d.Type
		}
	}

	// 4. Body Scan
	if d == nil {
		if d = matchPatterns(normalize(params.Body)); d != nil {
			d.Type = "Body Attack: " + d.Type
		}
	}

	if d != nil {
		if botD := CheckProbingBot(params.IP, d.Type); botD != nil {
			return botD
		}
		return d
	}
	return nil
}

func matchPatterns(input string) *Detection {
	if input == "" { return nil }
	maxScanSize := 1024 * 1024
	scanInput := input
	if len(input) > maxScanSize {
		scanInput = input[:maxScanSize]
	}
	for i, re := range compiledPatterns {
		if re.MatchString(scanInput) {
			return &patterns[i]
		}
	}
	return nil
}
