package models

// ThreatLevel defines the severity of a detected threat.
type ThreatLevel string

const (
	LevelLow      ThreatLevel = "LOW"
	LevelMedium   ThreatLevel = "MEDIUM"
	LevelHigh     ThreatLevel = "HIGH"
	LevelCritical ThreatLevel = "CRITICAL"
)

// Detection holds information about a security threat.
type Detection struct {
	Pattern string
	Level   ThreatLevel
	Type    string
}

// ScanParams contains all parameters required for a security scan.
type ScanParams struct {
	Method    string
	Path      string
	Query     string
	Body      string
	Headers   map[string][]string
	Cookies   map[string]string
	IP        string
	UserAgent string
	IsAI      bool
	
	// Dynamic Config from main
	MaxScanSize      int
	ProbingWindow    int
	ProbingThreshold int
	SpamThreshold    int
	AIScoreThreshold int
}
