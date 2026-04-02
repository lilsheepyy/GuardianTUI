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

var (
	// Advanced SQL Injection Heuristics
	sqliPatterns = []CompiledDetection{
		// 1. Tautologies & Logical Bypasses
		{
			Detection: models.Detection{Level: models.LevelCritical, Type: "SQLi: Tautology/Logic Bypass"},
			Regex:     regexp.MustCompile(`(?i)(['"]\s*OR\s*['"]?[^'"]+['"]?\s*=\s*['"]?[^'"]+['"]?)|(\bOR\s+\d+\s*=\s*\d+)|(\bOR\s+TRUE\b)`),
		},
		// 2. Union-Based & Join Attacks
		{
			Detection: models.Detection{Level: models.LevelCritical, Type: "SQLi: Union/Join Attack"},
			Regex:     regexp.MustCompile(`(?i)\bUNION\b(\s+ALL)?\s+SELECT\b|\bUNION\b\s*\/\*.*?\*\/|(?i)\bJOIN\b\s+.*?SELECT\b`),
		},
		// 3. Time-Based Blind SQLi (All major DBs)
		{
			Detection: models.Detection{Level: models.LevelCritical, Type: "SQLi: Time-Based/Blind"},
			Regex:     regexp.MustCompile(`(?i)pg_sleep\s*\(|benchmark\s*\(|WAITFOR\s+DELAY\b|dbms_lock\.sleep\s*\(|sqlite3_sleep\s*\(|\bsleep\s*\(\s*\d+\s*\)`),
		},
		// 4. Error-Based & Subqueries
		{
			Detection: models.Detection{Level: models.LevelHigh, Type: "SQLi: Error-Based/Subquery"},
			Regex:     regexp.MustCompile(`(?i)extractvalue\s*\(|updatexml\s*\(|ST_LatFromGeoHash|ST_LongFromGeoHash|exp\s*\(\s*~\s*0\s*\)|(?i)SELECT\s+.*?\s+FROM\s*\(SELECT\b`),
		},
		// 5. System Schema & Fingerprinting
		{
			Detection: models.Detection{Level: models.LevelCritical, Type: "SQLi: System Schema Access"},
			Regex:     regexp.MustCompile(`(?i)\binformation_schema\b|\bsysobjects\b|\bpg_catalog\b|\bsys\.tables\b|\bsqlite_master\b|\bpg_user\b|\bmysql\.user\b`),
		},
		// 6. Out-of-Band (OOB) & File Interaction
		{
			Detection: models.Detection{Level: models.LevelCritical, Type: "SQLi: OOB/File Interaction"},
			Regex:     regexp.MustCompile(`(?i)load_file\s*\(|into\s+outfile\b|into\s+dumpfile\b|utl_http\b|http_request\b|xp_cmdshell\b|sys_exec\b`),
		},
		// 7. Advanced Obfuscation (Hex/Char)
		{
			Detection: models.Detection{Level: models.LevelHigh, Type: "SQLi: Obfuscated Payload"},
			Regex:     regexp.MustCompile(`(?i)CHAR\s*\(\s*\d+.*?\)|0x[0-9a-fA-F]{4,}|(?i)EXEC\s*\(\s*0x`),
		},
	}

	// XSS & General Web Patterns (Recursive normalization handled in scanner)
	webPatterns = []CompiledDetection{
		{
			Detection: models.Detection{Level: models.LevelHigh, Type: "XSS: Script Injection"},
			Regex:     regexp.MustCompile(`(?i)<script.*?>|javascript:|on\w+\s*=|alert\s*\(|confirm\s*\(|prompt\s*\(`),
		},
		{
			Detection: models.Detection{Level: models.LevelMedium, Type: "Path Traversal"},
			Regex:     regexp.MustCompile(`(?i)\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c|/etc/passwd|/windows/win\.ini`),
		},
		{
			Detection: models.Detection{Level: models.LevelHigh, Type: "Command Injection"},
			Regex:     regexp.MustCompile(`(?i);\s*rm\s+-|\|\s*bash\b|;\s*cat\s+|&\s*powershell\b`),
		},
	}

	agentBlacklist = []string{
		"sqlmap", "nikto", "dirbuster", "gobuster", "acunetix", "wpscan", "masscan", "zgrab",
	}

	scannerHeaders = []string{
		"X-Scanner", "X-Waf-Test", "X-Nuclei-", "X-Forwarded-For-Poc",
	}
)

func MatchPatterns(input string, maxSize int) *models.Detection {
	if len(input) > maxSize {
		input = input[:maxSize]
	}

	// 1. Run Advanced SQLi Checks First
	for _, p := range sqliPatterns {
		if p.Regex.MatchString(input) {
			d := p.Detection
			d.Pattern = p.Regex.FindString(input)
			return &d
		}
	}

	// 2. Run General Web Attack Checks
	for _, p := range webPatterns {
		if p.Regex.MatchString(input) {
			d := p.Detection
			d.Pattern = p.Regex.FindString(input)
			return &d
		}
	}

	return nil
}

func CheckAgent(ua string) *models.Detection {
	for _, blocked := range agentBlacklist {
		if strings.Contains(strings.ToLower(ua), blocked) {
			return &models.Detection{Pattern: blocked, Level: models.LevelCritical, Type: "Offensive Tooling Detected"}
		}
	}
	return nil
}

func CheckScannerHeaders(key string) *models.Detection {
	for _, sh := range scannerHeaders {
		if strings.EqualFold(key, sh) || strings.HasPrefix(strings.ToLower(key), strings.ToLower(sh)) {
			return &models.Detection{Pattern: key, Level: models.LevelMedium, Type: "Scanner Header Detected"}
		}
	}
	return nil
}
