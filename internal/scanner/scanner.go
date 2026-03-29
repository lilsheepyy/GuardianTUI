package scanner

import (
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
	// SQL Injection & Evasions
	{Pattern: `(?i)(union(?:\s+all)?\s+select|select.*from|drop\s+table|insert\s+into|truncate\s+table|delete\s+from|waitfor\s+delay|1=1|' OR '1'='1)`, Level: LevelCritical, Type: "SQL Injection"},
	
	// Cross-Site Scripting (XSS)
	{Pattern: `(?i)(<script.*?>|javascript:|alert\s*\(|onerror\s*=|onclick\s*=|onload\s*=|document\.cookie)`, Level: LevelHigh, Type: "XSS Attempt"},
	
	// Path Traversal / LFI / RFI
	{Pattern: `(?i)(\.\.\/|\.\.\\|/etc/passwd|/windows/win\.ini|/proc/self/environ|file://|php://filter)`, Level: LevelCritical, Type: "Path Traversal / LFI"},
	
	// Command Injection / RCE
	{Pattern: `(?i)(;\s*ls|\|\s*id|` + "`" + `id` + "`" + `|\$\(id\)|exec\s*\(|system\s*\(|passthru\s*\(|shell_exec\s*\(|eval\s*\()`, Level: LevelCritical, Type: "Command Injection / RCE"},
	
	// Sensitive Data Exposure / Config Files
	{Pattern: `(?i)(\.env|wp-config\.php|id_rsa|\.aws/credentials|/.git/|docker-compose\.yml)`, Level: LevelCritical, Type: "Sensitive File Access"},
}

// Known malicious, scanner, or aggressive bot user agents
var maliciousAgents = []string{
	// Vulnerability Scanners
	"sqlmap", "nmap", "nikto", "dirbuster", "masscan", "zgrab", "nuclei", "burpsuite",
	"acunetix", "nessus", "qualys", "openvas", "netsparker", "arachni", "w3af", "havij",

	// Discovery & Enumeration Tools
	"gobuster", "wfuzz", "ffuf", "dirsearch", "feroxbuster", "rustbuster", "dirb",
	"amass", "subfinder", "httpx", "dnsx", "gau", "waybackpack", "hakrawler",
	"kiterunner", "arjun", "paramminer", "dotdotpwn",

	// CMS & Specialized Scanners
	"wpscan", "joomscan", "droopescan", "commix", "sslscan", "sslyze",

	// Exploitation Frameworks
	"metasploit", "msfconsole", "armitage", "beef",

	// Recon & Aggressive Crawlers
	"shodan", "censys", "binaryedge", "mj12bot", "ahrefsbot", "semrushbot", "dotbot",
	"rogerbot", "exabot", "proximic", "gigabot", "ia_archiver",
}

// Scanner-specific headers used by various tools
var scannerHeaders = []string{
	"X-Scanner", "X-Scanning-IP", "X-Scan-Type", "X-Bug-Bounty", "X-Scan-ID",
}

func Scan(input string, ip string, rHeaders map[string][]string, userAgent string) *Detection {
	// 1. Check Rate Limiting First
	if d := CheckRateLimit(ip); d != nil {
		return d
	}

	// 2. Check User Agent against Threat Intel
	uaLower := strings.ToLower(userAgent)
	for _, agent := range maliciousAgents {
		if strings.Contains(uaLower, agent) {
			return &Detection{
				Pattern: agent,
				Level:   LevelHigh,
				Type:    "Malicious Scanner / Bot",
			}
		}
	}

	// 3. Check for Scanner-Specific Headers
	for _, h := range scannerHeaders {
		if _, ok := rHeaders[h]; ok {
			return &Detection{
				Pattern: h,
				Level:   LevelMedium,
				Type:    "Scanner Signature Header",
			}
		}
	}

	// 4. Regex Signature Matching for Payloads
	for _, d := range patterns {
		re := regexp.MustCompile(d.Pattern)
		if re.MatchString(input) {
			return &d
		}
	}
...
	// 4. Payload Anomaly (Oversized Body or Headers)
	if len(input) > 8000 {
		return &Detection{
			Pattern: "Oversized Payload (>8KB)",
			Level:   LevelMedium,
			Type:    "Anomaly / Potential Buffer Overflow",
		}
	}

	return nil
}

func Clean(input string) string {
	return strings.ReplaceAll(strings.ReplaceAll(input, "\n", ""), "\r", "")
}