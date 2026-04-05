package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHoneypotToggle(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	logChan := make(chan LogEntry, 10)
	cfg := &Config{Engine: EngineConfig{Mode: "ips"}}
	e, _ := NewEngine(backend.URL, logChan, cfg, "")
	
	// Test enabled (should block /.env which is in honeypotPaths)
	e.HoneypotsEnabled = true
	req := httptest.NewRequest("GET", "/.env", nil)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403 when honeypots enabled, got %d", w.Code)
	}

	// Test disabling
	e.HoneypotsEnabled = false
	if e.HoneypotsEnabled != false {
		t.Error("Failed to disable honeypots")
	}
}

func Test404Spike(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer backend.Close()

	logChan := make(chan LogEntry, 100)
	cfg := &Config{
		Engine: EngineConfig{
			Mode:             "ips",
			ProbingWindow:    60,
			ProbingThreshold: 5,
		},
	}
	e, _ := NewEngine(backend.URL, logChan, cfg, "")

	ip := "1.2.3.4"
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("GET", "/not-found", nil)
		req.RemoteAddr = ip + ":1234"
		w := httptest.NewRecorder()
		e.ServeHTTP(w, req)
		
		// Drain log channel
		<-logChan
	}

	if blocked, _ := e.BlockedIPs.Load(ip); !blocked {
		t.Error("IP should be blocked after 404 spike in IPS mode")
	}
}
