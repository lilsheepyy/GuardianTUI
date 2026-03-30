package proxy

import (
	"bytes"
	"fmt"
	"guardiantui/internal/scanner"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

const blockPageTmpl = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Blocked | GuardianTUI</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0a0a0a; color: #e0e0e0; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .container { background-color: #1a1a1a; padding: 3rem; border-radius: 12px; border: 1px solid #333; box-shadow: 0 10px 30px rgba(0,0,0,0.5); text-align: center; max-width: 500px; }
        h1 { color: #ff4d4d; margin-top: 0; font-size: 2.5rem; }
        p { line-height: 1.6; color: #aaa; }
        .incident-id { background: #333; padding: 0.8rem; border-radius: 6px; font-family: monospace; color: #00ffcc; margin: 1.5rem 0; border: 1px dashed #555; font-size: 1.2rem; }
        .footer { font-size: 0.8rem; color: #555; margin-top: 2rem; }
        .shield { font-size: 4rem; margin-bottom: 1rem; }
    </style>
</head>
<body>
    <div class="container">
        <div class="shield">🛡️</div>
        <h1>Access Blocked</h1>
        <p>Your request has been flagged and blocked by the <strong>GuardianTUI</strong> security engine for suspicious activity.</p>
        <p>If you believe this is an error, please contact the administrator providing the following Incident ID:</p>
        <div class="incident-id">%s</div>
        <div class="footer">Powered by GuardianTUI L7 IPS Engine</div>
    </div>
</body>
</html>
`

type LogEntry struct {
	ID          string
	Timestamp   time.Time
	RemoteIP    string
	Method      string
	Path        string
	Agent       string
	Status      int
	Blocked     bool
	Alert       *scanner.Detection
	FullHeaders http.Header
	Payload     string
}

type Engine struct {
	TargetURL      *url.URL
	Proxy          *httputil.ReverseProxy
	BlockedIPs     sync.Map
	BlockedSubnets []*net.IPNet
	Whitelist      []*net.IPNet
	LogChan        chan LogEntry
	Config         *Config
	mu             sync.RWMutex
}

func NewEngine(target string, logChan chan LogEntry, cfg *Config) (*Engine, error) {
	u, err := url.Parse(target)
	if err != nil { return nil, err }
	e := &Engine{
		TargetURL: u,
		LogChan:   logChan,
		Config:    cfg,
	}
	e.Proxy = httputil.NewSingleHostReverseProxy(u)
	originalDirector := e.Proxy.Director
	e.Proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = u.Host
	}
	e.Proxy.ModifyResponse = e.modifyResponse
	return e, nil
}

func (e *Engine) IsWhitelisted(ipStr string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ip := net.ParseIP(ipStr)
	if ip == nil { return false }
	for _, subnet := range e.Whitelist {
		if subnet.Contains(ip) { return true }
	}
	return false
}

func (e *Engine) AddWhitelist(cidr string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !strings.Contains(cidr, "/") {
		if net.ParseIP(cidr).To4() != nil { cidr = cidr + "/32" } else { cidr = cidr + "/128" }
	}
	_, subnet, err := net.ParseCIDR(cidr)
	if err != nil { return err }
	e.Whitelist = append(e.Whitelist, subnet)
	return nil
}

func (e *Engine) AddBlockedSubnet(cidr string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !strings.Contains(cidr, "/") {
		if net.ParseIP(cidr).To4() != nil { cidr = cidr + "/32" } else { cidr = cidr + "/128" }
	}
	_, subnet, err := net.ParseCIDR(cidr)
	if err != nil { return err }
	e.BlockedSubnets = append(e.BlockedSubnets, subnet)
	return nil
}

func (e *Engine) IsIPBlockedBySubnet(ipStr string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ip := net.ParseIP(ipStr)
	if ip == nil { return false }
	for _, subnet := range e.BlockedSubnets {
		if subnet.Contains(ip) { return true }
	}
	return false
}

func (e *Engine) StartAutoUpdate() {
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		for range ticker.C {
			e.UpdateBlocklists()
		}
	}()
}

func (e *Engine) UpdateBlocklists() {
	var newSubnets []*net.IPNet
	
	// Ensure directory exists
	os.MkdirAll("proxylistblock", 0755)

	// Helper to process and save a list
	processList := func(name string, data string) {
		sanitized := e.parseDataToStrings(data)
		if len(sanitized) > 0 {
			// Save the CLEAN version for the user
			os.WriteFile(fmt.Sprintf("proxylistblock/%s", name), []byte(strings.Join(sanitized, "\n")), 0644)
			
			// Load into memory
			for _, cidr := range sanitized {
				if !strings.Contains(cidr, "/") {
					if net.ParseIP(cidr).To4() != nil { cidr = cidr + "/32" } else { cidr = cidr + "/128" }
				}
				_, subnet, err := net.ParseCIDR(cidr)
				if err == nil {
					newSubnets = append(newSubnets, subnet)
				}
			}
		}
	}

	// Load local blocklist
	if e.Config.BlocklistPath != "" {
		data, err := os.ReadFile(e.Config.BlocklistPath)
		if err == nil {
			processList("local_custom.txt", string(data))
		}
	}

	// Load remote blocklists
	client := &http.Client{Timeout: 20 * time.Second}
	for _, url := range e.Config.RemoteBlocklists {
		resp, err := client.Get(url)
		if err != nil { continue }
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil { continue }

		// Generate a short, identifiable name
		name := "list.txt"
		lowURL := strings.ToLower(url)
		if strings.Contains(lowURL, "spamhaus") { name = "spamhaus_drop.txt" } else if strings.Contains(lowURL, "abuseipdb") { name = "abuseipdb.txt" } else if strings.Contains(lowURL, "sslproxies") { name = "sslproxies.txt" } else if strings.Contains(lowURL, "firehol_proxies") { name = "firehol_proxies.txt" } else {
			urlParts := strings.Split(strings.TrimRight(url, "/"), "/")
			name = urlParts[len(urlParts)-1]
			if !strings.Contains(name, ".") { name += ".txt" }
		}

		processList(name, string(data))
	}

	e.mu.Lock()
	e.BlockedSubnets = newSubnets
	e.mu.Unlock()
}

func (e *Engine) parseDataToStrings(data string) []string {
	var result []string
	lines := strings.Split(data, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// 1. Ignore full-line comments (Spamhaus uses ;, others use #)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		
		// 2. Remove inline comments (e.g., "1.2.3.4 ; SBL123" or "1.2.3.4 # comment")
		if idx := strings.IndexAny(line, "#;"); idx != -1 {
			line = line[:idx]
		}
		
		// 3. Extract the first field (IP or CIDR)
		fields := strings.Fields(line)
		if len(fields) > 0 {
			cleanIP := strings.TrimSpace(fields[0])
			// Basic validation: must at least look like an IP or CIDR (contain dots or colons)
			if strings.Contains(cleanIP, ".") || strings.Contains(cleanIP, ":") {
				result = append(result, cleanIP)
			}
		}
	}
	return result
}

func (e *Engine) parseData(data string) []*net.IPNet {
	var subnets []*net.IPNet
	sanitized := e.parseDataToStrings(data)
	for _, cidr := range sanitized {
		if !strings.Contains(cidr, "/") {
			if net.ParseIP(cidr).To4() != nil { cidr = cidr + "/32" } else { cidr = cidr + "/128" }
		}
		_, subnet, err := net.ParseCIDR(cidr)
		if err == nil {
			subnets = append(subnets, subnet)
		}
	}
	return subnets
}

func (e *Engine) LoadBlocklist(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) { return nil }
		return err
	}
	return e.ParseBlocklist(string(data))
}

func (e *Engine) FetchRemoteBlocklist(url string) error {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil { return err }
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil { return err }

	return e.ParseBlocklist(string(data))
}

func (e *Engine) ParseBlocklist(data string) error {
	subnets := e.parseData(data)
	e.mu.Lock()
	e.BlockedSubnets = append(e.BlockedSubnets, subnets...)
	e.mu.Unlock()
	return nil
}

func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil { remoteIP = r.RemoteAddr }
	incidentID := uuid.New().String()[:8]

	if e.IsWhitelisted(remoteIP) {
		e.Proxy.ServeHTTP(w, r)
		return
	}

	// Check User-Agent blocklist
	if e.Config != nil {
		ua := r.UserAgent()
		for _, blockedUA := range e.Config.BlockedUserAgents {
			if strings.Contains(ua, blockedUA) {
				e.serveBlockPage(w, incidentID, remoteIP, r, &scanner.Detection{Type: "Blocked User-Agent", Pattern: blockedUA, Level: scanner.LevelCritical}, false)
				return
			}
		}
	}

	// Check IP blocklist (manual blocks and subnets)
	if _, blocked := e.BlockedIPs.Load(remoteIP); blocked {
		e.serveBlockPage(w, incidentID, remoteIP, r, nil, true)
		return
	}
	if e.IsIPBlockedBySubnet(remoteIP) {
		e.serveBlockPage(w, incidentID, remoteIP, r, &scanner.Detection{Type: "IP Blocklist", Level: scanner.LevelCritical}, false)
		return
	}

	var bodyCaptured string
	if r.Body != nil {
		body, _ := io.ReadAll(r.Body)
		bodyCaptured = string(body)
		r.Body = io.NopCloser(bytes.NewBuffer(body))
	}

	isAI := false
	if e.Config != nil {
		for _, ep := range e.Config.AIProtection.Endpoints {
			if strings.HasPrefix(r.URL.Path, ep) {
				isAI = true
				break
			}
		}
	}

	decodedPath, _ := url.PathUnescape(r.URL.Path)
	decodedQuery, _ := url.QueryUnescape(r.URL.RawQuery)

	scanParams := scanner.ScanParams{
		Method:    r.Method,
		Path:      decodedPath,
		Query:     decodedQuery,
		Body:      bodyCaptured,
		Headers:   r.Header,
		IP:        remoteIP,
		UserAgent: r.UserAgent(),
		IsAI:      isAI,
		
		// Injected Config
		MaxScanSize:      e.Config.Engine.MaxScanSize,
		ProbingWindow:    e.Config.Engine.ProbingWindow,
		ProbingThreshold: e.Config.Engine.ProbingThreshold,
		SpamThreshold:    e.Config.Engine.SpamThreshold,
		AIScoreThreshold: e.Config.AIProtection.ScoreThreshold,
	}

	detection := scanner.Scan(scanParams)

	if detection == nil && isAI && e.Config != nil {
		bodyLower := strings.ToLower(bodyCaptured)
		for _, kw := range e.Config.AIProtection.BlockedKeywords {
			if strings.Contains(bodyLower, strings.ToLower(kw)) {
				detection = &scanner.Detection{Pattern: kw, Level: scanner.LevelHigh, Type: "AI: Blocked Keyword"}
				break
			}
		}
	}

	if detection != nil {
		e.serveBlockPage(w, incidentID, remoteIP, r, detection, false)
		return
	}

	entry := LogEntry{
		ID:          incidentID,
		Timestamp:   time.Now(),
		RemoteIP:    remoteIP,
		Method:      r.Method,
		Path:        r.URL.Path,
		Agent:       r.UserAgent(),
		Alert:       nil,
		FullHeaders: r.Header,
		Payload:     bodyCaptured,
	}
	e.LogChan <- entry
	e.Proxy.ServeHTTP(w, r)
}

func (e *Engine) serveBlockPage(w http.ResponseWriter, id, ip string, r *http.Request, d *scanner.Detection, alreadyBlocked bool) {
	e.LogChan <- LogEntry{
		ID:          id,
		Timestamp:   time.Now(),
		RemoteIP:    ip,
		Method:      r.Method,
		Path:        r.URL.Path,
		Agent:       r.UserAgent(),
		Status:      403,
		Blocked:     true,
		Alert:       d,
		FullHeaders: r.Header,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(w, blockPageTmpl, id)
}

func (e *Engine) modifyResponse(res *http.Response) error { return nil }
func (e *Engine) Block(ip string) { e.BlockedIPs.Store(ip, true) }
func (e *Engine) Unblock(ip string) { e.BlockedIPs.Delete(ip) }
