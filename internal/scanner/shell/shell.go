package shell

import (
	"regexp"

	"guardiantui/internal/scanner/models"
)

type ShellPattern struct {
	Pattern     string
	Description string
	Regex       *regexp.Regexp
}

var shellPatterns = []ShellPattern{
	// --- BASH REVERSE SHELLS ---
	{`(?i)bash\s+-i\s*>\s*&\s*/dev/tcp/[0-9.]+/`, "Bash TCP Reverse Shell (/dev/tcp)", nil},
	{`(?i)bash\s+-i\s*>\s*&\s*/dev/udp/[0-9.]+/`, "Bash UDP Reverse Shell (/dev/udp)", nil},
	{`(?i)0>&[0-9]+\s*;?\s*exec\s*[0-9]+<>\s*/dev/tcp/`, "Bash Exec Descriptor Redirection", nil},

	// --- PYTHON REVERSE SHELLS ---
	{`(?i)import\s+socket\s*,\s*os\s*,\s*pty\s*;\s*s\s*=\s*socket\.socket`, "Python PTY Reverse Shell", nil},
	{`(?i)socket\.AF_INET\s*,\s*socket\.SOCK_STREAM\s*\)\s*;\s*s\.connect`, "Python Socket Connection", nil},
	{`(?i)os\.dup2\(\s*s\.fileno\(\)\s*,\s*[012]\s*\)`, "Python Socket Descriptor Duplication", nil},

	// --- PERL REVERSE SHELLS ---
	{`(?i)perl\s+-e\s*['"].*use\s+Socket\s*;.*socket\(.*S,PF_INET,SOCK_STREAM`, "Perl Socket Reverse Shell", nil},
	{`(?i)perl\s+-MIO\s*-e\s*['"].*\$p=fork;.*IO::Socket::INET->new`, "Perl IO::Socket Reverse Shell", nil},

	// --- PHP REVERSE SHELLS ---
	{`(?i)php\s+-r\s*['"].*\$sock\s*=\s*fsockopen\(.*exec\(.*sh\s+-i`, "PHP fsockopen Reverse Shell", nil},
	{`(?i)php\s+-r\s*['"].*shell_exec\(.*nc\s+-e\s+sh`, "PHP Netcat Execution", nil},

	// --- NETCAT REVERSE SHELLS ---
	{`(?i)nc\s+(-e|--exec)\s+/(bin/)?(ba)?sh`, "Netcat Execution Shield (-e sh)", nil},
	{`(?i)nc\s+(-c|--sh-exec)\s+/(bin/)?(ba)?sh`, "Netcat Execution Shield (-c sh)", nil},
	{`(?i)rm\s+[^;]+;\s*mkfifo\s+[^;]+;\s*cat\s+[^|]+\|\s*/bin/sh\s+-i`, "Netcat FIFO Backpipe Shell", nil},

	// --- POWERSHELL REVERSE SHELLS ---
	{`(?i)New-Object\s+System\.Net\.Sockets\.TCPClient\(.*\.GetStream\(\)`, "PowerShell TCPClient Shell", nil},
	{`(?i)IEX\s*\(New-Object\s+Net\.WebClient\)\.DownloadString\(.*tcp:`, "PowerShell TCP One-Liner", nil},

	// --- RUBY & OTHERS ---
	{`(?i)ruby\s+-rsocket\s*-e\s*['"].*TCPSocket\.new\(.*spawn\(.*sh\s+-i`, "Ruby TCPSocket Reverse Shell", nil},
	{`(?i)lua\s+-e\s*['"].*socket\s*=\s*require\(["']socket["']\).*tcp:connect`, "Lua Socket Reverse Shell", nil},
}

func init() {
	for i := range shellPatterns {
		shellPatterns[i].Regex = regexp.MustCompile(shellPatterns[i].Pattern)
	}
}

// AnalyzeShell checks input for common TCP/UDP reverse shell one-liners and socket redirection patterns.
func AnalyzeShell(input string) *models.Detection {
	for _, p := range shellPatterns {
		if p.Regex.MatchString(input) {
			return &models.Detection{
				Pattern: p.Pattern,
				Level:   models.LevelCritical,
				Type:    "Reverse Shell Shield - " + p.Description,
			}
		}
	}
	return nil
}
