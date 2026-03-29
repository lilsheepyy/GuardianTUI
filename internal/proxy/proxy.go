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

	"github.com/google/uuid"
)

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
	incidentID := uuid.New().String()[:8]

	if _, blocked := e.BlockedIPs.Load(remoteIP); blocked {
		e.LogChan <- LogEntry{
			ID:        incidentID,
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
	headersStr := fmt.Sprintf("%v", r.Header)
	payload := fmt.Sprintf("%s %s %s", r.Method, r.URL.Path, headersStr)
	detection := scanner.Scan(payload, remoteIP, r.UserAgent())

	var bodyCaptured string
	// Scan Body if possible
	if r.Body != nil {
		body, _ := io.ReadAll(r.Body)
		bodyCaptured = string(body)
		r.Body = io.NopCloser(bytes.NewBuffer(body))
		if d := scanner.Scan(bodyCaptured, remoteIP, r.UserAgent()); d != nil {
			detection = d
		}
	}

	entry := LogEntry{
		ID:          incidentID,
		Timestamp:   time.Now(),
		RemoteIP:    remoteIP,
		Method:      r.Method,
		Path:        r.URL.Path,
		Agent:       r.UserAgent(),
		Alert:       detection,
		FullHeaders: r.Header,
		Payload:     bodyCaptured,
	}

	if detection != nil && detection.Level == scanner.LevelCritical {
		// Auto block critical if you want, or just log
		entry.Blocked = false // Let user decide via TUI
	}

	e.LogChan <- entry
	e.Proxy.ServeHTTP(w, r)
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
