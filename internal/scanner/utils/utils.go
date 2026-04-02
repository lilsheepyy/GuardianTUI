package utils

import (
	"encoding/base64"
	"encoding/hex"
	"html"
	"math"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var (
	hexRegex     = regexp.MustCompile(`(?i)\\x[0-9a-f]{2}`)
	unicodeRegex = regexp.MustCompile(`(?i)\\u[0-9a-f]{4}`)
)

// Normalize recursively decodes URL, HTML, Base64, Hex, and Unicode strings.
func Normalize(input string) string {
	if input == "" { return "" }
	current := input
	
	// Recursively unwrap up to 4 layers of obfuscation
	for i := 0; i < 4; i++ {
		prev := current
		
		// 1. URL & HTML Unescape
		if decoded, err := url.QueryUnescape(current); err == nil { current = decoded }
		current = html.UnescapeString(current)
		
		// 2. Unicode Escape (\u0027 -> ')
		current = unicodeRegex.ReplaceAllStringFunc(current, func(s string) string {
			r, err := strconv.ParseInt(s[2:], 16, 32)
			if err == nil { return string(rune(r)) }
			return s
		})

		// 3. Hex Escape (\x27 -> ')
		current = hexRegex.ReplaceAllStringFunc(current, func(s string) string {
			r, err := strconv.ParseInt(s[2:], 16, 32)
			if err == nil { return string(rune(r)) }
			return s
		})

		// 4. Base64 (Only if likely encoded)
		if len(current) > 12 && !strings.Contains(current, " ") {
			if decoded, err := base64.StdEncoding.DecodeString(current); err == nil {
				current = string(decoded)
			}
		}

		// 5. Raw Hex (0x414243 -> ABC)
		if strings.HasPrefix(current, "0x") && len(current) > 4 {
			if decoded, err := hex.DecodeString(current[2:]); err == nil {
				current = string(decoded)
			}
		}

		if prev == current { break }
	}
	return current
}

// CalculateEntropy computes the Shannon entropy of a string.
// Higher values (e.g. > 5.0) indicate encrypted or packed data.
func CalculateEntropy(input string) float64 {
	if input == "" { return 0 }
	
	counts := make(map[rune]int)
	for _, char := range input {
		counts[char]++
	}
	
	var entropy float64
	inputLen := float64(len(input))
	for _, count := range counts {
		p := float64(count) / inputLen
		entropy -= p * math.Log2(p)
	}
	return entropy
}
