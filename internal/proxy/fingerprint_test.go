package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFingerprintGeneration(t *testing.T) {
	cfg := &Config{
		Engine: EngineConfig{MaxScanSize: 1024},
		AIProtection: AIConfig{ScoreThreshold: 5},
	}
	e, _ := NewEngine("http://localhost:80", make(chan LogEntry, 10), cfg, "")

	req1 := httptest.NewRequest("GET", "/", nil)
	req1.Header.Set("User-Agent", "Mozilla/5.0")
	req1.Header.Set("Accept", "text/html")
	req1.Header.Set("Accept-Language", "en-US")
	req1.Header.Set("Accept-Encoding", "gzip")
	req1.Header.Set("DNT", "1")

	fp1 := e.generateFingerprint(req1)

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("User-Agent", "Mozilla/5.0")
	req2.Header.Set("Accept", "text/html")
	req2.Header.Set("Accept-Language", "en-US")
	req2.Header.Set("Accept-Encoding", "gzip")
	req2.Header.Set("DNT", "1")

	fp2 := e.generateFingerprint(req2)

	if fp1 != fp2 {
		t.Errorf("Identical requests should have same fingerprint, got %s and %s", fp1, fp2)
	}

	req3 := httptest.NewRequest("GET", "/", nil)
	req3.Header.Set("User-Agent", "curl/7.68.0")
	fp3 := e.generateFingerprint(req3)

	if fp1 == fp3 {
		t.Errorf("Different requests should have different fingerprints, both got %s", fp1)
	}
}

func TestFingerprintBlocking(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	logChan := make(chan LogEntry, 10)
	cfg := &Config{
		Engine: EngineConfig{MaxScanSize: 1024, Mode: "ips"},
		AIProtection: AIConfig{ScoreThreshold: 5},
	}
	e, _ := NewEngine(backend.URL, logChan, cfg, "")

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("User-Agent", "Attacker-UA")
	req.Header.Set("Accept", "*/*")
	
	fp := e.generateFingerprint(req)
	
	// 1. Initially allowed
	w1 := httptest.NewRecorder()
	e.ServeHTTP(w1, req)
	if w1.Code != http.StatusOK {
		t.Errorf("Initial request should be allowed, got %d", w1.Code)
	}

	// 2. Block the fingerprint
	e.BlockedFingerprints.Store(fp, true)

	// 3. Subsequent request should be blocked
	w2 := httptest.NewRecorder()
	e.ServeHTTP(w2, req)
	if w2.Code != http.StatusForbidden {
		t.Errorf("Request with blocked fingerprint should be 403, got %d", w2.Code)
	}

	// 4. Request with different fingerprint should still be allowed
	reqClean := httptest.NewRequest("GET", "/", nil)
	reqClean.Header.Set("User-Agent", "Clean-UA")
	w3 := httptest.NewRecorder()
	e.ServeHTTP(w3, reqClean)
	if w3.Code != http.StatusOK {
		t.Errorf("Clean fingerprint should be allowed, got %d", w3.Code)
	}
}
