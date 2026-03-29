package scanner

import (
	"regexp"
	"strings"
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

var patterns = []Detection{
	{Pattern: `(?i)(union select|select.*from|drop table|insert into|truncate table|delete from)`, Level: LevelCritical, Type: "SQL Injection"},
	{Pattern: `(?i)(<script|alert\(|onerror|onclick|onload)`, Level: LevelHigh, Type: "XSS Attempt"},
	{Pattern: `(?i)(\.\.\/|\.\.\\|/etc/passwd|/windows/win\.ini|/proc/self/)`, Level: LevelCritical, Type: "Path Traversal"},
	{Pattern: `(?i)(admin|config|backup|setup|install)\.php`, Level: LevelMedium, Type: "Sensitive File Access"},
	{Pattern: `(?i)(exec\(|system\(|passthru\(|shell_exec\()`, Level: LevelCritical, Type: "Remote Code Execution"},
}

func Scan(input string) *Detection {
	for _, d := range patterns {
		re := regexp.MustCompile(d.Pattern)
		if re.MatchString(input) {
			return &d
		}
	}
	// Brute force detection would be stateful, we'll keep it simple for now
	if len(input) > 2000 {
		return &Detection{Pattern: "Oversized Payload", Level: LevelMedium, Type: "Dos Attempt"}
	}
	return nil
}

func Clean(input string) string {
	return strings.ReplaceAll(strings.ReplaceAll(input, "\n", ""), "\r", "")
}
