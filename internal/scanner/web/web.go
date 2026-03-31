package web

import (
	"regexp"
	"strings"

	"guardiantui/internal/scanner/models"
)

type CompiledDetection struct {
	Detection models.Detection
	Regex     *regexp.Regexp
}

// Base patterns for traditional web attacks
var rawPatterns = []models.Detection{
	// --- SQL Injection (Advanced) ---
	{Pattern: `(?i)(union(?:\s+all)?\s+select|select.*from|drop\s+table|insert\s+into|truncate\s+table|delete\s+from|waitfor\s+delay|1=1|' OR '1'='1|--|#|' OR 'x'='x|"\s+or\s+"x"="x|admin'\s+--|admin'\s+#|' OR TRUE--|"\s+OR\s+TRUE--|sqlite_master|pg_sleep|benchmark\(|information_schema)`, Level: models.LevelCritical, Type: "SQL Injection"},
	
	// --- XSS & DOM Injection ---
	{Pattern: `(?i)(<script.*?>|javascript:|alert\s*\(|onerror\s*=|onclick\s*=|onload\s*=|document\.cookie|<img\s+src=.*onerror=|<svg/onload=|<details/open/ontoggle=|<iframe/src=.*javascript:|onmouseover=)`, Level: models.LevelHigh, Type: "XSS Attempt"},
	
	// --- Path Traversal & LFI/RFI ---
	{Pattern: `(?i)(\.\.\/|\.\.\\|/etc/passwd|/etc/shadow|/etc/group|/windows/win\.ini|/proc/self/environ|file://|php://filter|expect://|zip://|data://|phar://|gopher://)`, Level: models.LevelCritical, Type: "Path Traversal / LFI"},
	
	// --- Command Injection & RCE ---
	{Pattern: `(?i)(;\s*ls|\|\s*id|` + "`" + `id` + "`" + `|\$\(id\)|exec\s*\(|system\s*\(|passthru\s*\(|shell_exec\s*\(|eval\s*\(|cat\s+/etc/|cat\${IFS}/etc/|uname\s+-a|/bin/sh|/bin/bash|python\s+-c|perl\s+-e|nc\s+-e|curl.*\|.*bash)`, Level: models.LevelCritical, Type: "Command Injection / RCE"},
	
	// --- SSRF (Server-Side Request Forgery) ---
	{Pattern: `(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.169\.254|metadata\.google\.internal|internal\.host|instance-data)`, Level: models.LevelHigh, Type: "SSRF Attempt"},
	
	// --- CRLF Injection / Header Splitting ---
	{Pattern: `(\r\n|\%0d\%0a|Set-Cookie:|Content-Type:.*multipart/|Location:.*http)`, Level: models.LevelMedium, Type: "CRLF / Header Injection"},

	// --- Sensitive Files & Credentials ---
	{Pattern: `(?i)(\.env|wp-config\.php|id_rsa|\.aws/credentials|/.git/|docker-compose\.yml|config\.json|web\.config|phpinfo\(\)|\.htaccess|\.htpasswd|bash_history)`, Level: models.LevelCritical, Type: "Sensitive File Access"},
	
	{Pattern: `(?i)(\$gt|\$ne|\$in|\$where|\$regex|\$expr|\$exists|\$and|\$or|\$not)`, Level: models.LevelHigh, Type: "NoSQL Injection"},
	{Pattern: `(?i)({{\s*.*?\s*}}|\${\s*.*?\s*}|<%\s*.*?\s*%>|{{7\*7}}|{{config\.items\(\)}})`, Level: models.LevelHigh, Type: "SSTI Attempt"},
}

var compiledPatterns []CompiledDetection

var maliciousAgents = []string{
	"sqlmap", "nmap", "nikto", "dirbuster", "masscan", "zgrab", "nuclei", "burpsuite",
	"acunetix", "nessus", "qualys", "openvas", "netsparker", "arachni", "w3af", "havij",
	"gobuster", "wfuzz", "ffuf", "dirsearch", "feroxbuster", "rustbuster", "dirb",
	"amass", "subfinder", "httpx", "dnsx", "gau", "waybackpack", "hakrawler",
	"shodan", "censys", "binaryedge", "mj12bot", "ahrefsbot", "semrushbot",
	"python-requests", "go-http-client", "curl", "wget", "libwww-perl", "php-http-client",
}

var scannerHeaders = []string{"X-Scanner", "X-Scanning-IP", "X-Scan-Type", "X-Bug-Bounty", "X-Scan-ID"}

func init() {
	for _, p := range rawPatterns {
		compiledPatterns = append(compiledPatterns, CompiledDetection{
			Detection: p,
			Regex:     regexp.MustCompile(p.Pattern),
		})
	}
}

// MatchPatterns checks the input against standard web attack vectors (SQLi, XSS, etc).
func MatchPatterns(input string, maxSize int) *models.Detection {
	if input == "" { return nil }
	scanInput := input
	if len(input) > maxSize { scanInput = input[:maxSize] }
	for _, cp := range compiledPatterns {
		if cp.Regex.MatchString(scanInput) { 
			return &models.Detection{
				Pattern: cp.Detection.Pattern,
				Level:   cp.Detection.Level,
				Type:    cp.Detection.Type,
			}
		}
	}
	return nil
}

// CheckAgent checks if the User-Agent is a known malicious scanner.
func CheckAgent(ua string) *models.Detection {
	uaLower := strings.ToLower(ua)
	for _, agent := range maliciousAgents {
		if strings.Contains(uaLower, agent) {
			return &models.Detection{Pattern: agent, Level: models.LevelHigh, Type: "Bot: Malicious Scanner"}
		}
	}
	return nil
}

// CheckScannerHeaders looks for headers commonly injected by vulnerability scanners.
func CheckScannerHeaders(key string) *models.Detection {
	for _, sh := range scannerHeaders {
		if strings.EqualFold(key, sh) {
			return &models.Detection{Pattern: key, Level: models.LevelMedium, Type: "Scanner Header Detected"}
		}
	}
	return nil
}
