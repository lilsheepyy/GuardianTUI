package dlp

import (
	"regexp"

	"guardiantui/internal/scanner/models"
)

type Pattern struct {
	Regex *regexp.Regexp
	Type  string
	Level models.ThreatLevel
}

var (
	// Response Patterns (Leaks from Backend)
	responsePatterns []Pattern
	// Request Patterns (Attempts to access files)
	requestPatterns []Pattern
)

func init() {
	// 1. Secrets & Tokens in Response Bodies
	rawResponsePatterns := []struct {
		Pattern string
		Type    string
		Level   models.ThreatLevel
	}{
		{`(?i)(?:AKIA|ASIA)[0-9A-Z]{16}`, "AWS Access Key", models.LevelHigh},
		{`(?i)gh[opr]_[a-zA-Z0-9]{36}`, "GitHub Token", models.LevelHigh},
		{`(?i)xox[bp]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}`, "Slack Token", models.LevelHigh},
		{`(?i)AIza[0-9A-Za-z-_]{35}`, "Google Cloud API Key", models.LevelHigh},
		{`(?i)sq0atp-[0-9A-Za-z\-_]{22}`, "Square Token", models.LevelHigh},
		{`(?i)sk_live_[0-9a-zA-Z]{24}`, "Stripe Live Key", models.LevelHigh},
		{`(?i)-----BEGIN [A-Z ]*PRIVATE KEY-----`, "Private Key Leakage", models.LevelCritical},
		{`(?i)SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}`, "SendGrid API Key", models.LevelHigh},
		{`(?i)key-[0-9a-zA-Z]{32}`, "Mailgun API Key", models.LevelHigh},
		{`(?i)(?:postgres|postgresql|mongodb|mongodb\+srv|mysql|redis|rediss):\/\/[^:]+:[^@]+@[^/]+`, "DB Connection String", models.LevelCritical},
		{`(?i)eyJ[a-zA-Z0-9]{10,}\.eyJ[a-zA-Z0-9]{10,}\.[a-zA-Z0-9-_]{20,}`, "JWT Token Leakage", models.LevelMedium},
	}

	for _, p := range rawResponsePatterns {
		responsePatterns = append(responsePatterns, Pattern{
			Regex: regexp.MustCompile(p.Pattern),
			Type:  "DLP: " + p.Type,
			Level: p.Level,
		})
	}

	// 2. Sensitive Filenames in Request Path
	rawRequestPatterns := []struct {
		Pattern string
		Type    string
		Level   models.ThreatLevel
	}{
		{`(?i)\.env$`, "Environment File Access", models.LevelCritical},
		{`(?i)\.git\/`, "Git Metadata Access", models.LevelHigh},
		{`(?i)id_rsa$|id_dsa$|id_ed25519$`, "SSH Private Key Access", models.LevelCritical},
		{`(?i)config\.php$|web\.config$|settings\.json$`, "Configuration File Access", models.LevelHigh},
		{`(?i)\.sql$|\.sqlite$|\.db$`, "Database File Access", models.LevelHigh},
		{`(?i)\.bash_history$|\.zsh_history$`, "Shell History Access", models.LevelHigh},
		{`(?i)docker-compose\.ya?ml$`, "Docker Compose File Access", models.LevelMedium},
	}

	for _, p := range rawRequestPatterns {
		requestPatterns = append(requestPatterns, Pattern{
			Regex: regexp.MustCompile(p.Pattern),
			Type:  "DLP: " + p.Type,
			Level: p.Level,
		})
	}
}

// AnalyzeResponse scans outgoing content for leaked secrets.
func AnalyzeResponse(input string) *models.Detection {
	for _, p := range responsePatterns {
		if p.Regex.MatchString(input) {
			return &models.Detection{
				Pattern: p.Regex.String(),
				Level:   p.Level,
				Type:    p.Type,
			}
		}
	}
	return nil
}

// AnalyzeRequest scans incoming paths for sensitive file access attempts.
func AnalyzeRequest(path string) *models.Detection {
	for _, p := range requestPatterns {
		if p.Regex.MatchString(path) {
			return &models.Detection{
				Pattern: p.Regex.String(),
				Level:   p.Level,
				Type:    p.Type,
			}
		}
	}
	return nil
}

// RedactSecrets replaces all matches of a pattern with a redacted string.
func RedactSecrets(input, pattern string) string {
	re := regexp.MustCompile(pattern)
	return re.ReplaceAllString(input, "[REDACTED SECRET]")
}
