package scanner

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
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

// Base patterns for traditional web attacks
var patterns = []Detection{
	{Pattern: `(?i)\b(cp|child porn|child pornography|csam|kiddie|pedo|pedophile|lolita|jailbait|cub)\b`, Level: LevelCritical, Type: "Anti-CSAM Shield / Illicit Content"},
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

// --- AI SHIELD V2: HEURISTICS ---

type AIHeuristic struct {
	Weight      int    `json:"weight"`
	Pattern     string `json:"pattern"`
	Description string `json:"description"`
}

var baseAIHeuristics = []AIHeuristic{
	{3, `(?i)(ignore|disregard|forget|bypass|overrule|reset|stop).*(previous|earlier|above).*(instructions|directions|guidelines|prompt)`, "Instruction Override"},
	{2, `(?i)(act as|you are now|imagine you are|pretend to be|roleplay as|start speaking as)`, "Roleplay/Persona Hijack"},
	{4, `(?i)(developer mode|dan mode|jailbreak|unfiltered|without restrictions|no constraints)`, "Jailbreak Signature"},
	{2, `(?i)(system prompt|initial instructions|hidden context|reveal your internal)`, "Prompt Leakage Attempt"},
	{3, `(?i)(translate the following and then execute|now in reverse|encode this and)`, "Obfuscation/Translation Bypass"},
	{2, `(?i)(Assistant:|System:|User:|Human:|### Instruction:)`, "Structural Hijacking"},
}

var customAIHeuristics []AIHeuristic
var compiledCustomPatterns []*regexp.Regexp

func LoadCustomAIRules(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) { return nil }
		return err
	}
	var rules []AIHeuristic
	if err := json.Unmarshal(data, &rules); err != nil { return err }
	customAIHeuristics = rules
	compiledCustomPatterns = make([]*regexp.Regexp, len(rules))
	for i, r := range rules { compiledCustomPatterns[i] = regexp.MustCompile(r.Pattern) }
	return nil
}

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

func CheckProbingBot(ip string, newType string, windowSec, probThreshold, spamThreshold int) *Detection {
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
		return &Detection{Pattern: "Diverse Vuln Testing", Level: LevelCritical, Type: "Vulnerability Probing Bot (Diverse)"}
	}
	if len(updatedHistory) >= spamThreshold && spamThreshold > 0 {
		return &Detection{Pattern: "High Frequency Probing", Level: LevelCritical, Type: "Vulnerability Probing Bot (Spam)"}
	}
	return nil
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
	IsAI      bool
	
	// Dynamic Config from main
	MaxScanSize      int
	ProbingWindow    int
	ProbingThreshold int
	SpamThreshold    int
	AIScoreThreshold int
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
		if d = matchPatterns(ua, params.MaxScanSize); d != nil { d.Type = "UA Attack: " + d.Type }
	}

	// 2. Headers
	if d == nil {
		for key, values := range params.Headers {
			normKey := normalize(key)
			if d = matchPatterns(normKey, params.MaxScanSize); d != nil { d.Type = "Header Key Attack: " + d.Type; break }
			for _, sh := range scannerHeaders {
				if strings.EqualFold(normKey, sh) { d = &Detection{Pattern: key, Level: LevelMedium, Type: "Scanner Header Detected"}; break }
			}
			if d != nil { break }
			for _, val := range values {
				normVal := normalize(val)
				if d = matchPatterns(normVal, params.MaxScanSize); d != nil { d.Type = "Header Value Attack: " + d.Type; break }
			}
			if d != nil { break }
		}
	}

	// 3. URL
	if d == nil {
		if d = matchPatterns(normalize(params.Path), params.MaxScanSize); d != nil { d.Type = "Path Attack: " + d.Type }
	}
	if d == nil {
		if d = matchPatterns(normalize(params.Query), params.MaxScanSize); d != nil { d.Type = "Query Attack: " + d.Type }
	}

	// 4. Body / AI Shield
	if d == nil {
		bodyNorm := normalize(params.Body)
		if params.IsAI {
			if d = analyzeAIAbuse(bodyNorm, params.AIScoreThreshold); d != nil {
				// AI detection
			}
		}
		if d == nil {
			if d = matchPatterns(bodyNorm, params.MaxScanSize); d != nil { d.Type = "Body Attack: " + d.Type }
		}
	}

	if d != nil {
		if botD := CheckProbingBot(params.IP, d.Type, params.ProbingWindow, params.ProbingThreshold, params.SpamThreshold); botD != nil {
			return botD
		}
		return d
	}
	return nil
}

func analyzeAIAbuse(input string, threshold int) *Detection {
	score := 0
	matchedPatterns := []string{}
	semanticInput := ""
	for _, r := range input {
		if unicode.IsLetter(r) || unicode.IsSpace(r) { semanticInput += string(r) }
	}
	semanticInput = strings.Join(strings.Fields(semanticInput), " ")

	for _, h := range baseAIHeuristics {
		if regexp.MustCompile(h.Pattern).MatchString(semanticInput) {
			score += h.Weight
			matchedPatterns = append(matchedPatterns, h.Description)
		}
	}
	for i, re := range compiledCustomPatterns {
		if re.MatchString(semanticInput) {
			score += customAIHeuristics[i].Weight
			matchedPatterns = append(matchedPatterns, customAIHeuristics[i].Description)
		}
	}

	if score >= threshold {
		return &Detection{
			Pattern: strings.Join(matchedPatterns, ", "),
			Level:   LevelHigh,
			Type:    fmt.Sprintf("AI Abuse: High Suspect Score (%d)", score),
		}
	}

	// PII
	piiPatterns := []string{
		`(?i)(4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})`, 
		`(?i)([0-9]{3}-[0-9]{2}-[0-9]{4})`,
	}
	for _, p := range piiPatterns {
		if regexp.MustCompile(p).MatchString(input) {
			return &Detection{Pattern: "Sensitive Pattern", Level: LevelMedium, Type: "AI: PII Data Leakage"}
		}
	}
	return nil
}

func normalize(input string) string {
	if input == "" { return "" }
	current := input
	for i := 0; i < 3; i++ {
		prev := current
		if decoded, err := url.QueryUnescape(current); err == nil { current = decoded }
		current = html.UnescapeString(current)
		if len(current) > 12 && !strings.Contains(current, " ") {
			if decoded, err := base64.StdEncoding.DecodeString(current); err == nil { current = string(decoded) }
		}
		if prev == current { break }
	}
	return current
}

func matchPatterns(input string, maxSize int) *Detection {
	if input == "" { return nil }
	scanInput := input
	if len(input) > maxSize { scanInput = input[:maxSize] }
	for i, d := range patterns {
		if regexp.MustCompile(d.Pattern).MatchString(scanInput) { return &patterns[i] }
	}
	return nil
}
