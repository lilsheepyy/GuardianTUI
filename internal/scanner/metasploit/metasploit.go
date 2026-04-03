package metasploit

import (
	"regexp"
	"strings"

	"guardiantui/internal/scanner/models"
)

type MetasploitPattern struct {
	Pattern     string
	Description string
	Regex       *regexp.Regexp
}

var msfPatterns = []MetasploitPattern{
	// --- METERPRETER HTTP/S TRANSPORT ---
	{`(?i)/[a-zA-Z0-9_-]{22}[a-zA-Z0-9_-]{8,106}/?$`, "Meterpreter Long UUID URI", nil},
	{`(?i)\bRECV\b`, "Meterpreter Session Polling (RECV)", nil},
	
	// --- POWERSHELL STAGERS (Common in MSF Web Delivery) ---
	{`(?i)New-Object\s+System\.Net\.WebClient`, "PowerShell WebClient Stager", nil},
	{`(?i)DownloadData\(.*\).*[System\.Reflection\.Assembly]::Load`, "PowerShell Memory Injection Stager", nil},
	{`(?i)WinHttp\.WinHttpRequest\.5\.1`, "PowerShell WinHttp Stager", nil},
	{`(?i)IEX\s*\(New-Object\s+Net\.WebClient\).DownloadString`, "PowerShell One-Liner Download/Execute", nil},
	{`(?i)-ExecutionPolicy\s+Bypass\s+-WindowStyle\s+Hidden`, "PowerShell Stealth Execution Flags", nil},
	{`(?i)PowerShell\s+-NoP\s+-NonI\s+-W\s+Hidden\s+-Enc`, "PowerShell Base64 Encoded Command", nil},

	// --- COBALT STRIKE & EMPIRE INDICATORS ---
	{`(?i)\b(reflectiveLoader|GetProcAddress|VirtualAlloc|CreateRemoteThread)\b`, "WinAPI Memory Injection Signature", nil},
	{`(?i)\b(beacon\.dll|beacon\.exe|stager\.dll|stager\.exe)\b`, "Cobalt Strike Beacon Signature", nil},
	{`(?i)/___/`, "Empire Default URI Pattern", nil},
	{`(?i)/admin/get\.php\?session=`, "Empire Session URI Pattern", nil},

	// --- EXPLOIT MODULE PAYLOADS ---
	{`(?i)jndi:(ldap|rmi|dns|nis|iiop|corba|lds|http):`, "Log4j Remote Class Loading (JNDI)", nil},
	{`(?i)ognl\.OgnlContext`, "Struts2 OGNL Injection", nil},
	{`(?i)java\.lang\.ProcessBuilder`, "Java RCE Payload Indicator", nil},
	{`(?i)ysoserial`, "Common Java Deserialization Exploit Tool", nil},
	{`(?i)T(String)?Object(Stream)?`, "Delphi/C++ Deserialization Payload", nil},
	
	// --- MISC MSF INDICATORS ---
	{`(?i)\bMETERPRETER_TRANSPORT_HTTP\b`, "Meterpreter Transport ID", nil},
	{`(?i)msfconsole`, "Metasploit Console Indicator", nil},
	{`(?i)meterpreter`, "Meterpreter String Indicator", nil},
	{`(?i)payload_type\s*=\s*['"]meterpreter['"]`, "MSF Payload Type Definition", nil},
}

func init() {
	for i := range msfPatterns {
		msfPatterns[i].Regex = regexp.MustCompile(msfPatterns[i].Pattern)
	}
}

// AnalyzeMSF checks input for common Metasploit payload and exploit signatures.
func AnalyzeMSF(input string) *models.Detection {
	for _, p := range msfPatterns {
		if p.Regex.MatchString(input) {
			return &models.Detection{
				Pattern: p.Pattern,
				Level:   models.LevelCritical,
				Type:    "Metasploit/Exploit Shield - " + p.Description,
			}
		}
	}
	return nil
}

// CheckChecksum validates if a URI matches the Metasploit 8-bit checksum logic.
func CheckChecksum(uri string) *models.Detection {
	// Remove leading slash
	cleanURI := strings.TrimPrefix(uri, "/")
	if len(cleanURI) == 0 { return nil }

	// Calculate 8-bit checksum (sum mod 256)
	var sum int
	for i := 0; i < len(cleanURI); i++ {
		sum += int(cleanURI[i])
	}
	checksum := sum % 256

	// Common MSF Checksums: 
	// 92: INITW (Windows Native), 88: INITJ (Java), 80: INITP (Python), 98: CONN (Established)
	switch checksum {
	case 92, 88, 80, 98:
		return &models.Detection{
			Pattern:     uri,
			Level:       models.LevelHigh,
			Type:        "Metasploit: Heuristic URI Checksum Match",
		}
	}
	return nil
}
