package proxy

import (
	"bytes"
	"fmt"
	"guardiantui/internal/scanner"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"
)

type LogEntry struct {
	ID        string
	Timestamp time.Time
	RemoteIP  string
	Method    string
	Path      string
	Agent     string
	Status    int
	Blocked   bool
	Alert     *scanner.Detection
}

type Engine struct {
	TargetURL *url.URL
	Proxy     *httputil.ReverseProxy
	BlockedIPs sync.Map
	LogChan   chan LogEntry
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

func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	remoteIP := r.RemoteAddr
	if _, blocked := e.BlockedIPs.Load(remoteIP); blocked {
		e.LogChan <- LogEntry{
			Timestamp: time.Now(),
			RemoteIP:  remoteIP,
			Method:    r.Method,
			Path:      r.URL.Path,
			Status:    403,
			Blocked:   true,
		}
		http.Error(w, "Access Blocked by GuardianTUI", http.StatusForbidden)
		return
	}

	// Scan headers and path
	payload := fmt.Sprintf("%s %s %v", r.Method, r.URL.Path, r.Header)
	detection := scanner.Scan(payload)

	// Scan Body if possible
	if r.Body != nil {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewBuffer(body))
		if d := scanner.Scan(string(body)); d != nil {
			detection = d
		}
	}

	entry := LogEntry{
		Timestamp: time.Now(),
		RemoteIP:  remoteIP,
		Method:    r.Method,
		Path:      r.URL.Path,
		Agent:     r.UserAgent(),
		Alert:     detection,
	}

	if detection != nil && detection.Level == scanner.LevelCritical {
		// Auto block critical if you want, or just log
		entry.Blocked = false // Let user decide via TUI
	}

	e.LogChan <- entry
	e.Proxy.ServeHTTP(w, r)
}

func (e *Engine) modifyResponse(res *http.Response) error {
	// Here we could capture status codes if needed
	return nil
}

func (e *Engine) Block(ip string) {
	e.BlockedIPs.Store(ip, true)
}

func (e *Engine) Unblock(ip string) {
	e.BlockedIPs.Delete(ip)
}
