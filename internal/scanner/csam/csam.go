package csam

import (
	"fmt"
	"regexp"
	"strings"

	"guardiantui/internal/scanner/models"
)

// CSAMHeuristic defines a heuristic rule for detecting illicit content.
type CSAMHeuristic struct {
	Weight      int
	Pattern     string
	Description string
	Regex       *regexp.Regexp
}

var csamHeuristics = []CSAMHeuristic{
	// Level 5: Direct & Critical (Instant Block)
	{Weight: 5, Pattern: `(?i)\b(child[ _-]?(porn|pornography|sex|abuse|rape|pornografy))\b`, Description: "Direct CSAM Terminology"},
	{Weight: 5, Pattern: `(?i)\b(cp|csam|kiddie|pedo|pedophile|pedofilia|pedofilo|lolita|jailbait|cub)\b`, Description: "Illicit Slang/Acronyms"},
	{Weight: 5, Pattern: `(?i)\b(pre-?teen|underage|minor|child).*(porn|sex|nude|naked)\b`, Description: "Illicit Combinations"},
	
	// Level 2-3: Suspicious Context (Requires combination to block)
	{Weight: 3, Pattern: `(?i)\b(young|little|small|tiny).*(girl|boy|child|kid).*(nude|naked|action)\b`, Description: "Suspicious Context: Age + Content"},
	{Weight: 2, Pattern: `(?i)\b(links|mega|drive|folder|pack|collection).*(cp|csam|kiddie)\b`, Description: "Distribution Attempt"},
	{Weight: 3, Pattern: `(?i)\b(barely|legal|teen|school).*(girl|boy)\b`, Description: "Borderline/High-Risk Content"},
	{Weight: 2, Pattern: `(?i)\b(trade|exchange|buy|sell|request).*(cp|csam)\b`, Description: "Solicitation Indicators"},
}

var leetspeakReplacer *strings.Replacer

func init() {
	for i := range csamHeuristics {
		csamHeuristics[i].Regex = regexp.MustCompile(csamHeuristics[i].Pattern)
	}
	leetspeakReplacer = strings.NewReplacer(
		"@", "a", "4", "a", "3", "e", "1", "i", "!", "i", "0", "o", "7", "t", "5", "s", "$", "s",
	)
}

// AnalyzeCSAM checks input against zero-tolerance heuristics for illicit content.
func AnalyzeCSAM(input string) *models.Detection {
	score := 0
	matched := []string{}
	
	normalizedInput := leetspeakReplacer.Replace(strings.ToLower(input))

	for _, h := range csamHeuristics {
		if h.Regex.MatchString(normalizedInput) {
			score += h.Weight
			matched = append(matched, h.Description)
			
			if h.Weight >= 5 {
				return &models.Detection{
					Pattern: h.Pattern,
					Level:   models.LevelCritical,
					Type:    "ZERO TOLERANCE: CSAM Shield - " + h.Description,
				}
			}
		}
	}

	if score >= 5 {
		return &models.Detection{
			Pattern: strings.Join(matched, " | "),
			Level:   models.LevelCritical,
			Type:    fmt.Sprintf("ZERO TOLERANCE: CSAM Heuristic Score (%d)", score),
		}
	}
	return nil
}
