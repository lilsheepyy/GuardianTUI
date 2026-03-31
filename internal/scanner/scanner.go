package scanner

import (
	"strings"

	"guardiantui/internal/scanner/ai"
	"guardiantui/internal/scanner/bot"
	"guardiantui/internal/scanner/csam"
	"guardiantui/internal/scanner/metasploit"
	"guardiantui/internal/scanner/models"
	"guardiantui/internal/scanner/pii"
	"guardiantui/internal/scanner/utils"
	"guardiantui/internal/scanner/web"
)

// We re-export types from models so external packages (proxy, main) 
// don't have to change their imports extensively.
type Detection = models.Detection
type ScanParams = models.ScanParams
type ThreatLevel = models.ThreatLevel

const (
	LevelLow      = models.LevelLow
	LevelMedium   = models.LevelMedium
	LevelHigh     = models.LevelHigh
	LevelCritical = models.LevelCritical
)

// LoadCustomAIRules delegates to the ai package.
func LoadCustomAIRules(path string) error {
	return ai.LoadCustomAIRules(path)
}

// Scan performs a comprehensive inspection of an HTTP request.
func Scan(params ScanParams) *Detection {
	var d *Detection

	// 1. ZERO TOLERANCE: CSAM SHIELD
	// High-priority heuristic check across all request components
	var parts []string
	if params.Path != "" { parts = append(parts, params.Path) }
	if params.Query != "" { parts = append(parts, params.Query) }
	if params.Body != "" { parts = append(parts, params.Body) }
	combinedInput := utils.Normalize(strings.Join(parts, " "))
	
	if csamDet := csam.AnalyzeCSAM(combinedInput); csamDet != nil {
		return csamDet
	}

	// 2. Metasploit/Exploit Shield
	if d = metasploit.CheckChecksum(params.Path); d != nil {
		return d
	}
	if d = metasploit.AnalyzeMSF(combinedInput); d != nil {
		return d
	}

	// 3. User Agent
	ua := utils.Normalize(params.UserAgent)
	if d = web.CheckAgent(ua); d != nil {
		// Handled by web.CheckAgent
	} else if d = web.MatchPatterns(ua, params.MaxScanSize); d != nil {
		d.Type = "UA Attack: " + d.Type
	}

	// 3. Headers
	if d == nil {
		for key, values := range params.Headers {
			normKey := utils.Normalize(key)
			
			// Skip the "Cookie" header as we handle cookies granularly below
			if strings.EqualFold(normKey, "cookie") {
				continue
			}

			if d = web.MatchPatterns(normKey, params.MaxScanSize); d != nil {
				d.Type = "Header Key Attack: " + d.Type
				break
			}
			if d = web.CheckScannerHeaders(normKey); d != nil {
				break
			}
			for _, val := range values {
				normVal := utils.Normalize(val)
				if d = web.MatchPatterns(normVal, params.MaxScanSize); d != nil {
					d.Type = "Header Value Attack: " + d.Type
					break
				}
			}
			if d != nil { break }
		}
	}

	// 4. Cookies (Granular Inspection)
	if d == nil {
		for name, value := range params.Cookies {
			normName := utils.Normalize(name)
			normVal := utils.Normalize(value)

			if d = web.MatchPatterns(normName, params.MaxScanSize); d != nil {
				d.Type = "Cookie Name Attack: " + d.Type
				break
			}
			if d = web.MatchPatterns(normVal, params.MaxScanSize); d != nil {
				d.Type = "Cookie Value Attack: " + d.Type
				break
			}
		}
	}

	// 5. URL (Path & Query)
	if d == nil {
		if d = web.MatchPatterns(utils.Normalize(params.Path), params.MaxScanSize); d != nil {
			d.Type = "Path Attack: " + d.Type
		}
	}
	if d == nil {
		if d = web.MatchPatterns(utils.Normalize(params.Query), params.MaxScanSize); d != nil {
			d.Type = "Query Attack: " + d.Type
		}
	}

	// 5. Body / AI Shield / PII
	if d == nil {
		bodyNorm := utils.Normalize(params.Body)
		if params.IsAI {
			if aiD := ai.AnalyzeAIAbuse(bodyNorm, params.AIScoreThreshold); aiD != nil {
				d = aiD
			}
		}
		// If AI didn't catch it or not an AI endpoint, check PII and general patterns
		if d == nil {
			if piiD := pii.AnalyzePII(bodyNorm); piiD != nil {
				d = piiD
			} else if webD := web.MatchPatterns(bodyNorm, params.MaxScanSize); webD != nil {
				d = webD
				d.Type = "Body Attack: " + d.Type
			}
		}
	}

	// 6. Probing Bot Detection
	if d != nil {
		if botD := bot.CheckProbingBot(params.IP, d.Type, params.ProbingWindow, params.ProbingThreshold, params.SpamThreshold); botD != nil {
			return botD
		}
		return d
	}

	return nil
}
