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
		{
			Detection: models.Detection{Level: models.LevelCritical, Type: "SQLi: Tautology/Logic Bypass"},
			Regex:     regexp.MustCompile(`(?i)(['"]\s*OR\s*['"]?[^'"]+['"]?\s*=\s*['"]?[^'"]+['"]?)|(\bOR\s+\d+\s*=\s*\d+)|(\bOR\s+TRUE\b)`),
		},
		{
			Detection: models.Detection{Level: models.LevelCritical, Type: "SQLi: Union/Join Attack"},
			Regex:     regexp.MustCompile(`(?i)\bUNION\b(\s+ALL)?\s+SELECT\b|\bUNION\b\s*\/\*.*?\*\/|(?i)\bJOIN\b\s+.*?SELECT\b`),
		},
		{
			Detection: models.Detection{Level: models.LevelCritical, Type: "SQLi: sqlmap/Exploit Specific Payload"},
			Regex:     regexp.MustCompile(`(?i)UNION\s+ALL\s+SELECT\s+NULL|(?i)AND\s+\d+=\d+\s*AND\s*\(SELECT\b|(?i)CASE\s+WHEN\s+\d+=\d+\s+THEN\s+\d+\s+ELSE\b|(?i)GROUP\s+BY\s+CONCAT|(?i)EXTRACTVALUE\s*\(|(?i)UPDATEXML\s*\(`),
		},
		{
			Detection: models.Detection{Level: models.LevelCritical, Type: "SQLi: Time-Based/Blind"},
			Regex:     regexp.MustCompile(`(?i)pg_sleep\s*\(|benchmark\s*\(|WAITFOR\s+DELAY\b|dbms_lock\.sleep\s*\(|sqlite3_sleep\s*\(|\bsleep\s*\(\s*\d+\s*\)`),
		},
		{
			Detection: models.Detection{Level: models.LevelHigh, Type: "SQLi: Error-Based/Subquery"},
			Regex:     regexp.MustCompile(`(?i)extractvalue\s*\(|updatexml\s*\(|ST_LatFromGeoHash|ST_LongFromGeoHash|exp\s*\(\s*~\s*0\s*\)|(?i)SELECT\s+.*?\s+FROM\s*\(SELECT\b`),
		},
		{
			Detection: models.Detection{Level: models.LevelCritical, Type: "SQLi: System Schema Access"},
			Regex:     regexp.MustCompile(`(?i)\binformation_schema\b|\bsysobjects\b|\bpg_catalog\b|\bsys\.tables\b|\bsqlite_master\b|\bpg_user\b|\bmysql\.user\b`),
		},
		{
			Detection: models.Detection{Level: models.LevelCritical, Type: "SQLi: OOB/File Interaction"},
			Regex:     regexp.MustCompile(`(?i)load_file\s*\(|into\s+outfile\b|into\s+dumpfile\b|utl_http\b|http_request\b|xp_cmdshell\b|sys_exec\b`),
		},
		{
			Detection: models.Detection{Level: models.LevelHigh, Type: "SQLi: Obfuscated Payload"},
			Regex:     regexp.MustCompile(`(?i)CHAR\s*\(\s*\d+.*?\)|0x[0-9a-fA-F]{4,}|(?i)EXEC\s*\(\s*0x`),
		},
	}

	// Advanced RCE & Command Injection Heuristics
	rcePatterns = []CompiledDetection{
		{
			Detection: models.Detection{Level: models.LevelCritical, Type: "RCE: System Discovery Command"},
			Regex:     regexp.MustCompile(`(?i)[;&|]\s*(whoami|id|ls|cat|dir|uname|hostname|ifconfig|ipconfig|netstat|ps|env|printenv|tasklist)\b`),
		},
		{
			Detection: models.Detection{Level: models.LevelCritical, Type: "RCE: Execution Wrapper"},
			Regex:     regexp.MustCompile("(?i)`.*?`|\\$\\(.*?\\)"),
		},
		{
			Detection: models.Detection{Level: models.LevelHigh, Type: "RCE: Dangerous Binary/Script"},
			Regex:     regexp.MustCompile(`(?i);\s*rm\s+-|\|\s*bash\b|;\s*sh\b|;\s*python\b|&\s*powershell\b|;\s*nc\s+|;\s*curl\s+|;\s*wget\s+`),
		},
	}

	// Advanced Path Traversal Heuristics
	traversalPatterns = []CompiledDetection{
		{
			Detection: models.Detection{Level: models.LevelCritical, Type: "Path Traversal: Direct Bypass"},
			Regex:     regexp.MustCompile(`(?i)\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c|%252e%252e%252f|%252e%252e%255c`),
		},
		{
			Detection: models.Detection{Level: models.LevelCritical, Type: "Path Traversal: Sensitive OS File"},
			Regex:     regexp.MustCompile(`(?i)\/etc\/(passwd|shadow|group|hosts|hostname|issue|motd)|Windows\/System32|win\.ini|boot\.ini`),
		},
		{
			Detection: models.Detection{Level: models.LevelHigh, Type: "Path Traversal: App Metadata/Secrets"},
			Regex:     regexp.MustCompile(`(?i)\.env|\.git\/|\.ssh\/|id_rsa|id_dsa|docker-compose\.yml|config\.php|wp-config\.php|web\.config|appsettings\.json`),
		},
	}

	// Advanced XSS (Cross-Site Scripting) Shield
	xssPatterns = []CompiledDetection{
		{
			Detection: models.Detection{Level: models.LevelHigh, Type: "XSS: Script Tag Injection"},
			Regex:     regexp.MustCompile(`(?i)<script.*?>|&lt;script.*?>|%3cscript.*?>`),
		},
		{
			Detection: models.Detection{Level: models.LevelHigh, Type: "XSS: Inline Event Handler"},
			Regex:     regexp.MustCompile(`(?i)\bon[a-z]+\s*=\s*['"]?.*?['"]?|(?i)\bon[a-z]+\s*=\s*[^\s>]+`),
		},
		{
			Detection: models.Detection{Level: models.LevelHigh, Type: "XSS: Pseudo-Protocol"},
			Regex:     regexp.MustCompile(`(?i)(javascript|data|vbscript|onload|onerror):`),
		},
		{
			Detection: models.Detection{Level: models.LevelHigh, Type: "XSS: SVG/XML Vector"},
			Regex:     regexp.MustCompile(`(?i)<svg.*?onload|(?i)<details.*?ontoggle|(?i)<img.*?onerror|(?i)<iframe.*?src=['"]?javascript:`),
		},
		{
			Detection: models.Detection{Level: models.LevelMedium, Type: "XSS: DOM/Global Manipulation"},
			Regex:     regexp.MustCompile(`(?i)\beval\s*\(|\balert\s*\(|\bconfirm\s*\(|\bprompt\s*\(|\bdocument\.cookie\b|\bwindow\.location\b|\bString\.fromCharCode\b`),
		},
	}

	// Advanced Buffer Overflow & Shellcode Heuristics
	overflowPatterns = []CompiledDetection{
		{
			Detection: models.Detection{Level: models.LevelCritical, Type: "Exploit: NOP Sled Detected"},
			Regex:     regexp.MustCompile(`(?i)(\\x90|0x90){8,}|(\x90){8,}`),
		},
		{
			Detection: models.Detection{Level: models.LevelHigh, Type: "Exploit: Potential Buffer Overflow"},
			Regex:     regexp.MustCompile(`(?i)A{128,}|[a-zA-Z0-9]{999,}|%{10,}[snpx]`),
		},
		{
			Detection: models.Detection{Level: models.LevelCritical, Type: "Exploit: Shellcode Pattern"},
			Regex:     regexp.MustCompile(`(?i)\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}`),
		},
	}

	agentBlacklist = []string{
		"sqlmap", "nikto", "dirbuster", "gobuster", "acunetix", "wpscan", "masscan", "zgrab",
		"commix", "nmap", "nessus", "openvas", "burpsuite", "zap", "arachni", "wfuzz",
		"dirb", "metasploit", "nuclei", "shodan", "censys", "netsparker", "qualys",
		"havij", "pangolin", "sql-ninja", "skipfish", "golismero", "webscarab",
		"maltego", "spiderfoot", "beEF", "hydra", "medusa", "john", "hashcat",
	}

	scannerHeaders = []string{
		"X-Scanner", "X-Waf-Test", "X-Nuclei-", "X-Forwarded-For-Poc",
		"X-Sqlmap-", "X-Zap-", "X-Acunetix-", "X-Burp-", "X-Netsparker-",
		"X-Appscan-", "X-Wxs-", "X-Scanner-",
	}
)

func MatchPatterns(input string, maxSize int) *models.Detection {
	if len(input) > maxSize {
		input = input[:maxSize]
	}

	// 1. Run Buffer Overflow / Exploit Checks (High Priority)
	for _, p := range overflowPatterns {
		if p.Regex.MatchString(input) {
			d := p.Detection
			d.Pattern = p.Regex.FindString(input)
			return &d
		}
	}

	// 2. Run RCE / Command Injection Checks
	for _, p := range rcePatterns {
		if p.Regex.MatchString(input) {
			d := p.Detection
			d.Pattern = p.Regex.FindString(input)
			return &d
		}
	}

	// 3. Run Advanced SQLi Checks
	for _, p := range sqliPatterns {
		if p.Regex.MatchString(input) {
			d := p.Detection
			d.Pattern = p.Regex.FindString(input)
			return &d
		}
	}

	// 4. Run Advanced XSS Checks
	for _, p := range xssPatterns {
		if p.Regex.MatchString(input) {
			d := p.Detection
			d.Pattern = p.Regex.FindString(input)
			return &d
		}
	}

	// 5. Run Path Traversal Checks
	for _, p := range traversalPatterns {
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
