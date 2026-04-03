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
	{Weight: 5, Pattern: `(?i)\b(child[ _-]?(porn|pornography|sex|abuse|rape|pornografy|molest|molestation|prod|teen|infant|minor|underage))\b`, Description: "Direct CSAM Terminology"},
	{Weight: 5, Pattern: `(?i)\b(cp|csam|kiddie|pedo|pedophile|pedofilia|pedofilo|lolita|jailbait|cub|pre-?teen|underage|minor|infant|toddler|loli|shota|shotalo|loli-?con|pedobear|childlove|boylove|girllove|younglove)\b`, Description: "Illicit Slang/Acronyms"},
	{Weight: 5, Pattern: `(?i)\b(pre-?teen|underage|minor|child|kid|boy|girl).*(porn|sex|nude|naked|action|video|image|photo|collection|pack|link|mega|drive|folder|archive|rar|zip|zip-?line|leak|tape|movie)\b`, Description: "Illicit Combinations"},
	{Weight: 5, Pattern: `(?i)\b(kinder|bebe|nino|nina|joven|adolescente).*(porno|sexo|desnudo|abuso|violacion)\b`, Description: "Multilingual CSAM Variants"},
	
	// Level 2-3: Suspicious Context (Requires combination to block)
	{Weight: 3, Pattern: `(?i)\b(young|little|small|tiny|cute|pretty|sweet).*(girl|boy|child|kid|infant|toddler|daughter|son).*(nude|naked|action|bedroom|bathroom|shower|pool|diaper|undies|underwear)\b`, Description: "Suspicious Context: Age + Content"},
	{Weight: 2, Pattern: `(?i)\b(links|mega|drive|folder|pack|collection|stash|vault|cloud|box|pastebin|telegraph|anonfiles).*(cp|csam|kiddie|loli|shota)\b`, Description: "Distribution Attempt"},
	{Weight: 3, Pattern: `(?i)\b(barely|legal|teen|school|middle[ -]?school|high[ -]?school|college).*(girl|boy|student|uniform|skirt|locker[ -]?room)\b`, Description: "Borderline/High-Risk Content"},
	{Weight: 2, Pattern: `(?i)\b(trade|exchange|buy|sell|request|leak|shared|dm|pm|discord|telegram|session|wickr).*(cp|csam|loli|shota)\b`, Description: "Solicitation Indicators"},
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
