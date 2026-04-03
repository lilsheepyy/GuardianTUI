package web

import (
	"testing"
)

func TestCheckAgent(t *testing.T) {
	tests := []struct {
		ua       string
		expected bool
	}{
		{"Mozilla/5.0 (sqlmap/1.4.12#stable http://sqlmap.org)", true},
		{"sqlmap/1.4.12#stable", true},
		{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", false},
		{"nikto/2.1.6", true},
		{"burpsuite", true},
	}

	for _, tt := range tests {
		det := CheckAgent(tt.ua)
		if (det != nil) != tt.expected {
			t.Errorf("CheckAgent(%q) = %v, expected %v", tt.ua, det, tt.expected)
		}
	}
}

func TestMatchPatternsSQLmap(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"UNION ALL SELECT NULL,NULL,NULL--", true},
		{"AND 1=1 AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)", true},
		{"(SELECT (CASE WHEN (1=1) THEN 1 ELSE (SELECT 2 FROM information_schema.tables) END))", true},
		{"NORMAL_STRING", false},
	}

	for _, tt := range tests {
		det := MatchPatterns(tt.input, 1000)
		if (det != nil) != tt.expected {
			t.Errorf("MatchPatterns(%q) = %v, expected %v", tt.input, det, tt.expected)
		}
	}
}

func TestCheckScannerHeaders(t *testing.T) {
	tests := []struct {
		header   string
		expected bool
	}{
		{"X-Sqlmap-Scan-Id", true},
		{"X-Zap-Scan-Id", true},
		{"X-Scanner-Info", true},
		{"Content-Type", false},
	}

	for _, tt := range tests {
		det := CheckScannerHeaders(tt.header)
		if (det != nil) != tt.expected {
			t.Errorf("CheckScannerHeaders(%q) = %v, expected %v", tt.header, det, tt.expected)
		}
	}
}
