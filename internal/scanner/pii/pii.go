package pii

import (
	"regexp"

	"guardiantui/internal/scanner/models"
)

var compiledPIIPatterns []*regexp.Regexp

func init() {
	piiPatterns := []string{
		`(?i)(4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})`, // Credit Cards (Visa, MC, Amex, Disc)
		`(?i)([0-9]{3}-[0-9]{2}-[0-9]{4})`,                                                       // SSN
		`(?i)(xox[pb]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})`,                               // Slack Token
		`(?i)(AIza[0-9A-Za-z-_]{35})`,                                                            // Google API Key
		`(?i)(sk_live_[0-9a-zA-Z]{24})`,                                                          // Stripe Live Key
		`(?i)(?:^|[^\w])(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,39})(?:$|[^\w])`, // Bitcoin Address
	}
	for _, p := range piiPatterns {
		compiledPIIPatterns = append(compiledPIIPatterns, regexp.MustCompile(p))
	}
}

// AnalyzePII checks input for sensitive data leakage like Credit Cards or SSNs.
func AnalyzePII(input string) *models.Detection {
	for _, re := range compiledPIIPatterns {
		if re.MatchString(input) {
			return &models.Detection{
				Pattern: "Sensitive Pattern",
				Level:   models.LevelMedium,
				Type:    "AI: PII Data Leakage",
			}
		}
	}
	return nil
}
