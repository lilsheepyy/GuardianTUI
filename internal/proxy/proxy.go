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
	TargetURL  *url.URL
	Proxy      *httputil.ReverseProxy
	BlockedIPs sync.Map
	Whitelist  []*net.IPNet
	LogChan    chan LogEntry
	mu         sync.RWMutex
}

func NewEngine(target string, logChan chan LogEntry) (*Engine, error) {
	u, err := url.Parse(target)
	if err != nil {
		return nil, err
	}

	e := &Engine{
		TargetURL: u,
		LogChan:   logChan,
	}

	e.Proxy = httputil.NewSingleHostReverseProxy(u)
	e.Proxy.ModifyResponse = e.modifyResponse
	
	return e, nil
}

func (e *Engine) IsWhitelisted(remoteIP string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	ipStr := remoteIP
	if strings.Contains(ipStr, ":") {
		host, _, err := net.SplitHostPort(ipStr)
		if err == nil {
			ipStr = host
		}
	}
	
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, subnet := range e.Whitelist {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

func (e *Engine) AddWhitelist(cidr string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !strings.Contains(cidr, "/") {
		if net.ParseIP(cidr).To4() != nil {
			cidr = cidr + "/32"
		} else {
			cidr = cidr + "/128"
		}
	}

	_, subnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	e.Whitelist = append(e.Whitelist, subnet)
	return nil
}

func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	remoteIP := r.RemoteAddr
	incidentID := uuid.New().String()[:8]

	if e.IsWhitelisted(remoteIP) {
		e.Proxy.ServeHTTP(w, r)
		return
	}

	// 1. Check if IP is already permanently blocked
	if _, blocked := e.BlockedIPs.Load(remoteIP); blocked {
		e.serveBlockPage(w, incidentID, remoteIP, r, nil, true)
		return
	}

	// 2. Capture Body for scanning
	var bodyCaptured string
	if r.Body != nil {
		body, _ := io.ReadAll(r.Body)
		bodyCaptured = string(body)
		r.Body = io.NopCloser(bytes.NewBuffer(body))
	}

	// Decode Path and Query for more accurate scanning (prevents bypasses via URL encoding)
	decodedPath, _ := url.PathUnescape(r.URL.Path)
	decodedQuery, _ := url.QueryUnescape(r.URL.RawQuery)

	// Prepare exhaustive scan parameters
	scanParams := scanner.ScanParams{
		Method:    r.Method,
		Path:      decodedPath,
		Query:     decodedQuery,
		Body:      bodyCaptured,
		Headers:   r.Header,
		IP:        remoteIP,
		UserAgent: r.UserAgent(),
	}

	detection := scanner.Scan(scanParams)

	// 4. Block if threat detected
	if detection != nil {
		e.serveBlockPage(w, incidentID, remoteIP, r, detection, false)
		return
	}

	// 5. Log and Proxy if safe
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
	// Send log entry as blocked
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
	return nil
}

func (e *Engine) Block(ip string) {
	e.BlockedIPs.Store(ip, true)
}

func (e *Engine) Unblock(ip string) {
	e.BlockedIPs.Delete(ip)
}
