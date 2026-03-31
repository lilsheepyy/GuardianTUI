package pii

import (
	"regexp"

	"guardiantui/internal/scanner/models"
)

var compiledPIIPatterns []*regexp.Regexp

func init() {
	piiPatterns := []string{
		`(?i)(4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})`, // Credit Cards
		`(?i)([0-9]{3}-[0-9]{2}-[0-9]{4})`,                           // SSN
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
