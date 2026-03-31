package utils

import (
	"encoding/base64"
	"html"
	"net/url"
	"strings"
)

// Normalize recursively decodes URL, HTML, and Base64 encoded strings to reveal obfuscated payloads.
func Normalize(input string) string {
	if input == "" { return "" }
	current := input
	for i := 0; i < 3; i++ {
		prev := current
		if decoded, err := url.QueryUnescape(current); err == nil { current = decoded }
		current = html.UnescapeString(current)
		if len(current) > 12 && !strings.Contains(current, " ") {
			if decoded, err := base64.StdEncoding.DecodeString(current); err == nil { current = string(decoded) }
		}
		if prev == current { break }
	}
	return current
}
