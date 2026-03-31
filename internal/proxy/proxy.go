package proxy

import (
	"bytes"
	"fmt"
	"guardiantui/internal/proxy/pow"
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
	TargetURL       *url.URL
	Proxy           *httputil.ReverseProxy
	BlockedIPs      sync.Map
	BlockedSubnets  []*net.IPNet
	BlockedExactIPs map[string]bool
	Whitelist       []*net.IPNet
	LogChan         chan LogEntry
	Config          *Config
	PoW             *pow.System
	mu              sync.RWMutex
}

func NewEngine(target string, logChan chan LogEntry, cfg *Config) (*Engine, error) {
	u, err := url.Parse(target)
	if err != nil { return nil, err }
	
	var powSys *pow.System
	if cfg != nil && cfg.Engine.PoWEnabled {
		powSys = pow.NewSystem(cfg.Engine.PoWDifficulty, "")
	}

	e := &Engine{
		TargetURL: u,
		LogChan:   logChan,
		Config:    cfg,
		PoW:       powSys,
	}
	e.Proxy = httputil.NewSingleHostReverseProxy(u)
	originalDirector := e.Proxy.Director
	e.Proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = u.Host
		// Identification cookie for license and tracking
		req.AddCookie(&http.Cookie{Name: "guardianTUI", Value: "true"})
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

func (e *Engine) parseCIDR(cidr string) (*net.IPNet, error) {
	if !strings.Contains(cidr, "/") {
		if ip := net.ParseIP(cidr); ip != nil {
			if ip.To4() != nil { cidr += "/32" } else { cidr += "/128" }
		}
	}
	_, subnet, err := net.ParseCIDR(cidr)
	return subnet, err
}

func (e *Engine) AddWhitelist(cidr string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	subnet, err := e.parseCIDR(cidr)
	if err != nil { return err }
	e.Whitelist = append(e.Whitelist, subnet)
	return nil
}

func (e *Engine) AddBlockedSubnet(cidr string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	subnet, err := e.parseCIDR(cidr)
	if err != nil { return err }
	e.BlockedSubnets = append(e.BlockedSubnets, subnet)
	return nil
}

func (e *Engine) StartAutoUpdate() {
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		for range ticker.C {
			e.UpdateBlocklists()
		}
	}()
}

func (e *Engine) sanitizer(data string) (cleaned []string, subnets []*net.IPNet, exactIPs map[string]bool) {
	exactIPs = make(map[string]bool)
	lines := strings.Split(data, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") { continue }
		if idx := strings.IndexAny(line, "#;"); idx != -1 { line = line[:idx] }
		
		fields := strings.Fields(line)
		if len(fields) > 0 {
			cleanIP := strings.TrimSpace(fields[0])
			if strings.Contains(cleanIP, ".") || strings.Contains(cleanIP, ":") {
				if !strings.Contains(cleanIP, "/") {
					// It's an exact IP
					if ip := net.ParseIP(cleanIP); ip != nil {
						exactIPs[ip.String()] = true
						cleaned = append(cleaned, cleanIP)
					}
				} else {
					// It's a subnet
					if subnet, err := e.parseCIDR(cleanIP); err == nil {
						cleaned = append(cleaned, cleanIP)
						subnets = append(subnets, subnet)
					}
				}
			}
		}
	}
	return
}

func (e *Engine) UpdateBlocklists() {
	var allSubnets []*net.IPNet
	allExactIPs := make(map[string]bool)
	os.MkdirAll("proxylistblock", 0755)

	process := func(name, data string) {
		cleanStrings, subnets, exactIPs := e.sanitizer(data)
		if len(cleanStrings) > 0 {
			// Save the CLEAN, SANITIZED version
			os.WriteFile(fmt.Sprintf("proxylistblock/%s", name), []byte(strings.Join(cleanStrings, "\n")), 0644)
			allSubnets = append(allSubnets, subnets...)
			for ip := range exactIPs {
				allExactIPs[ip] = true
			}
		}
	}

	// 1. Process local blocklist
	if e.Config.BlocklistPath != "" {
		if data, err := os.ReadFile(e.Config.BlocklistPath); err == nil {
			process("local_custom.txt", string(data))
		}
	}

	// 2. Process remote blocklists
	client := &http.Client{Timeout: 30 * time.Second}
	for _, url := range e.Config.RemoteBlocklists {
		resp, err := client.Get(url)
		if err != nil { continue }
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil { continue }

		name := "list.txt"
		lowURL := strings.ToLower(url)
		if strings.Contains(lowURL, "spamhaus") { name = "spamhaus_drop.txt" } else if strings.Contains(lowURL, "abuseipdb") { name = "abuseipdb.txt" } else if strings.Contains(lowURL, "sslproxies") { name = "sslproxies.txt" } else if strings.Contains(lowURL, "firehol_proxies") { name = "firehol_proxies.txt" } else {
			parts := strings.Split(strings.TrimRight(url, "/"), "/")
			name = parts[len(parts)-1]
			if !strings.Contains(name, ".") { name += ".txt" }
		}
		process(name, string(data))
	}

	// 3. Atomically swap the active subnets and exact IPs
	e.mu.Lock()
	e.BlockedSubnets = allSubnets
	e.BlockedExactIPs = allExactIPs
	e.mu.Unlock()
}

func (e *Engine) LoadBlocklist(path string) error {
	data, err := os.ReadFile(path)
	if err != nil { return err }
	return e.ParseBlocklist(string(data))
}

func (e *Engine) FetchRemoteBlocklist(url string) error {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil { return err }
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil { return err }
	return e.ParseBlocklist(string(data))
}

func (e *Engine) ParseBlocklist(data string) error {
	_, subnets, exactIPs := e.sanitizer(data)
	e.mu.Lock()
	e.BlockedSubnets = append(e.BlockedSubnets, subnets...)
	if e.BlockedExactIPs == nil {
		e.BlockedExactIPs = make(map[string]bool)
	}
	for ip := range exactIPs {
		e.BlockedExactIPs[ip] = true
	}
	e.mu.Unlock()
	return nil
}

func (e *Engine) IsIPBlockedBySubnet(ipStr string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	ip := net.ParseIP(ipStr)
	if ip == nil { return false }
	parsedStr := ip.String()

	// O(1) lookup for exact IPs
	if e.BlockedExactIPs != nil && e.BlockedExactIPs[parsedStr] {
		return true
	}

	// O(N) lookup for subnets
	for _, subnet := range e.BlockedSubnets {
		if subnet.Contains(ip) { return true }
	}
	return false
}

func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil { remoteIP = r.RemoteAddr }
	incidentID := uuid.New().String()[:8]

	// Determine if this is an AI endpoint
	isAI := false
	reqPath := r.URL.Path
	if e.Config != nil {
		for _, ep := range e.Config.AIProtection.Endpoints {
			if strings.HasPrefix(reqPath, ep) {
				isAI = true
				break
			}
		}
	}

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

	decodedPath, _ := url.PathUnescape(r.URL.Path)
	decodedQuery, _ := url.QueryUnescape(r.URL.RawQuery)

	// Extract Cookies for granular scanning
	cookieMap := make(map[string]string)
	for _, cookie := range r.Cookies() {
		cookieMap[cookie.Name] = cookie.Value
	}

	scanParams := scanner.ScanParams{
		Method:    r.Method,
		Path:      decodedPath,
		Query:     decodedQuery,
		Body:      bodyCaptured,
		Headers:   r.Header,
		Cookies:   cookieMap,
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

	// Transparent PoW Challenge Handling (Only for requests that passed the security scan)
	if e.PoW != nil && e.Config.Engine.PoWEnabled {
		// Only challenge GET requests (to avoid breaking APIs) and only if not whitelisted
		if r.Method == "GET" && !strings.Contains(r.Header.Get("Accept"), "application/json") {
			powCookie, err := r.Cookie("gtui_pow")
			powVerified := false
			
			if err == nil && powCookie != nil {
				// Verify solution: challenge|nonce
				decoded, _ := url.QueryUnescape(powCookie.Value)
				parts := strings.SplitN(decoded, "|", 2)
				if len(parts) == 2 {
					if e.PoW.ValidateSolution(remoteIP, parts[0], parts[1]) {
						powVerified = true
					}
				}
			}
			
			if !powVerified {
				// Send invisible JS challenge
				challenge := e.PoW.GenerateChallenge(remoteIP)
				html := e.PoW.JSInjector(challenge)
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.Header().Set("Cache-Control", "no-store, max-age=0")
				w.WriteHeader(http.StatusServiceUnavailable) // Using 503 to prevent indexing of challenge page
				w.Write([]byte(html))
				return
			}
		}
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

func (e *Engine) SendHeartbeat() {
	if e.Config == nil || e.Config.TelemetryEnabled == nil || !*e.Config.TelemetryEnabled {
		return
	}
	
	// Real-time anonymous pulse via CounterAPI.dev
	// This request increments the active instance counter.
	url := "https://api.counterapi.dev/v2/sheeps-team-3543/guardiantui/up"
	client := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err == nil {
		req.Header.Set("Authorization", "Bearer ut_aTIPkcxdEveuOq6u5oV6hLnEYD3tG6T47sbHQWDk")
		req.Header.Set("User-Agent", "GuardianTUI-Heartbeat")
		res, err := client.Do(req)
		if err == nil { res.Body.Close() }
	}
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

func (e *Engine) modifyResponse(res *http.Response) error {
	// Identification cookie for license and identification purpose
	cookie := &http.Cookie{
		Name:  "guardianTUI",
		Value: "true",
		Path:  "/",
	}
	res.Header.Add("Set-Cookie", cookie.String())

	// Method 1: Custom HTTP Header
	res.Header.Set("X-Protected-By", "GuardianTUI")

	// Method 5: Via Header
	res.Header.Add("Via", "1.1 guardianTUI")

	return nil
}
func (e *Engine) Block(ip string) { e.BlockedIPs.Store(ip, true) }
func (e *Engine) Unblock(ip string) { e.BlockedIPs.Delete(ip) }
