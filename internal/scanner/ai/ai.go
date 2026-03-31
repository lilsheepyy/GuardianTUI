package ai

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode"

	"guardiantui/internal/scanner/csam"
	"guardiantui/internal/scanner/models"
)

// AIHeuristic defines a heuristic rule for detecting AI abuse.
type AIHeuristic struct {
	Weight      int            `json:"weight"`
	Pattern     string         `json:"pattern"`
	Description string         `json:"description"`
	Regex       *regexp.Regexp `json:"-"`
}

var baseAIHeuristics = []AIHeuristic{
	// --- ZERO TOLERANCE: AI CSAM SHIELD ---
	// Improved patterns to detect combinations regardless of order
	{Weight: 5, Pattern: `(?i)(generate|create|write|describe|imagine).*((child|minor|underage|kiddie|pedo).* (porn|nude|sex|naked|erotica)|(porn|nude|sex|naked|erotica).*(child|minor|underage|kiddie|pedo|kid))`, Description: "AI: CSAM Generation Attempt"},
	{Weight: 5, Pattern: `(?i)(roleplay|act as|pretend).*((child|minor|underage|kiddie|pedo).* (porn|nude|sex|naked|erotica)|(porn|nude|sex|naked|erotica).*(child|minor|underage|kiddie|pedo|kid))`, Description: "AI: CSAM Roleplay Attempt"},
	{Weight: 4, Pattern: `(?i)(bypassing|ignoring|overriding).*(safety|filter|restriction).*(child|minor|csam|kid)`, Description: "AI: Safety Bypass for Illicit Content"},

	// --- Standard AI Safety ---
	{Weight: 3, Pattern: `(?i)(ignore|disregard|forget|bypass|overrule|reset|stop).*(instruction|direction|guideline|prompt)`, Description: "Instruction Override"},
	{Weight: 2, Pattern: `(?i)(act as|you are now|imagine you are|pretend to be|roleplay as|start speaking as)`, Description: "Roleplay/Persona Hijack"},
	{Weight: 4, Pattern: `(?i)(developer mode|dan mode|jailbreak|unfiltered|without restrictions|no constraints)`, Description: "Jailbreak Signature"},
	{Weight: 2, Pattern: `(?i)(system prompt|initial instructions|hidden context|reveal your internal)`, Description: "Prompt Leakage Attempt"},
	{Weight: 3, Pattern: `(?i)(translate the following and then execute|now in reverse|encode this and)`, Description: "Obfuscation/Translation Bypass"},
	{Weight: 2, Pattern: `(?i)(Assistant:|System:|User:|Human:|### Instruction:)`, Description: "Structural Hijacking"},
}

var customAIHeuristics []AIHeuristic

func init() {
	for i := range baseAIHeuristics {
		baseAIHeuristics[i].Regex = regexp.MustCompile(baseAIHeuristics[i].Pattern)
	}
}

// LoadCustomAIRules loads custom AI rules from a JSON file.
func LoadCustomAIRules(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) { return nil }
		return err
	}
	var rules []AIHeuristic
	if err := json.Unmarshal(data, &rules); err != nil { return err }
	
	for i := range rules {
		rules[i].Regex = regexp.MustCompile(rules[i].Pattern)
	}
	customAIHeuristics = rules
	return nil
}

// AnalyzeAIAbuse checks an AI prompt for jailbreaks, prompt injection, and CSAM generation attempts.
func AnalyzeAIAbuse(input string, threshold int) *models.Detection {
	if csamDet := csam.AnalyzeCSAM(input); csamDet != nil {
		return csamDet
	}

	score := 0
	matchedPatterns := []string{}
	semanticInput := ""
	for _, r := range input {
		if unicode.IsLetter(r) || unicode.IsSpace(r) { semanticInput += string(r) }
	}
	semanticInput = strings.Join(strings.Fields(semanticInput), " ")

	for _, h := range baseAIHeuristics {
		if h.Regex.MatchString(semanticInput) {
			score += h.Weight
			matchedPatterns = append(matchedPatterns, h.Description)
		}
	}
	for _, h := range customAIHeuristics {
		if h.Regex.MatchString(semanticInput) {
			score += h.Weight
			matchedPatterns = append(matchedPatterns, h.Description)
		}
	}

	if score >= threshold {
		return &models.Detection{
			Pattern: strings.Join(matchedPatterns, ", "),
			Level:   models.LevelHigh,
			Type:    fmt.Sprintf("AI Abuse: High Suspect Score (%d)", score),
		}
	}

	return nil
}
