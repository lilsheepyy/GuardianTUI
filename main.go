package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"guardiantui/internal/crypto"
	"guardiantui/internal/proxy"
	"guardiantui/internal/scanner"
	"guardiantui/internal/tui"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	bubbletea "github.com/charmbracelet/bubbletea"
	"golang.org/x/crypto/acme/autocert"
)

// LogSchema defines the JSON structure for persistent logs
type LogSchema struct {
	Timestamp  string            `json:"timestamp"`
	ID         string            `json:"incident_id"`
	RemoteIP   string            `json:"remote_ip"`
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Status     int               `json:"status"`
	Blocked    bool              `json:"blocked"`
	Alert      *scanner.Detection `json:"alert,omitempty"`
	UserAgent  string            `json:"user_agent"`
	Headers    http.Header       `json:"headers,omitempty"`
}

func main() {
	target := flag.String("target", "http://localhost:80", "Target URL to protect")
	listen := flag.String("listen", ":8080", "Listen address for the proxy")
	
	// Create logs folder by default
	logsDir := "logs"
	os.MkdirAll(logsDir, 0755)
	defaultLogPath := filepath.Join(logsDir, "guardian.json")
	
	logFile := flag.String("log", defaultLogPath, "Path to the log file")
	configFile := flag.String("config", "config.yaml", "Path to the YAML config file")
	aiRulesFile := flag.String("ai-rules", "ai.json", "Path to the AI custom rules JSON file")
	
	domain := flag.String("domain", "", "Auto-provision real Let's Encrypt SSL for this domain")
	whitelistFlag := flag.String("whitelist", "", "Comma-separated list of IPs or CIDR ranges to whitelist")
	useHTTPS := flag.Bool("https", false, "Enable local self-signed HTTPS mode")
	headless := flag.Bool("headless", false, "Run without TUI (useful for background/production)")
	flag.Parse()

	// Load Config
	cfg, err := proxy.LoadConfig(*configFile)
	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		os.Exit(1)
	}

	// Load AI Rules
	if err := scanner.LoadCustomAIRules(*aiRulesFile); err != nil {
		fmt.Printf("Error loading AI rules: %v\n", err)
		os.Exit(1)
	}

	rawLogChan := make(chan proxy.LogEntry, 100)
	tuiChan := make(chan proxy.LogEntry, 100)

	// Log Worker with Rotation and JSON support
	go func() {
		for entry := range rawLogChan {
			tuiChan <- entry
			
			// 1. Prepare JSON Log Entry
			schema := LogSchema{
				Timestamp: entry.Timestamp.Format(time.RFC3339),
				ID:        entry.ID,
				RemoteIP:  entry.RemoteIP,
				Method:    entry.Method,
				Path:      entry.Path,
				Status:    entry.Status,
				Blocked:   entry.Blocked,
				Alert:     entry.Alert,
				UserAgent: entry.Agent,
				Headers:   entry.FullHeaders,
			}
			
			jsonData, _ := json.Marshal(schema)
			
			// 2. Persistent Storage with Rotation Check
			rotateAndWrite(*logFile, jsonData)
		}
	}()

	engine, err := proxy.NewEngine(*target, rawLogChan, cfg)
	if err != nil {
		fmt.Printf("Error starting engine: %v\n", err)
		os.Exit(1)
	}

	// Opt-in Telemetry Prompt
	if cfg != nil && !cfg.TelemetryAsked {
		fmt.Print("\n🛡️  Help improve GuardianTUI? (Anonymous Heartbeat to GitHub) [y/N]: ")
		var resp string
		fmt.Scanln(&resp)
		resp = strings.ToLower(resp)
		enabled := resp == "y" || resp == "yes"
		cfg.TelemetryEnabled = &enabled
		cfg.TelemetryAsked = true
		cfg.Save(*configFile)
		fmt.Println("Selection saved to config.yaml")
	}

	// Start Heartbeat if enabled
	if cfg != nil && cfg.TelemetryEnabled != nil && *cfg.TelemetryEnabled {
		go func() {
			for {
				engine.SendHeartbeat()
				time.Sleep(24 * time.Hour)
			}
		}()
	}

	if cfg != nil {
		for _, ip := range cfg.Whitelist { engine.AddWhitelist(ip) }
	}

	engine.UpdateBlocklists()
	engine.StartAutoUpdate()

	if *whitelistFlag != "" {
		ips := strings.Split(*whitelistFlag, ",")
		for _, ip := range ips { engine.AddWhitelist(strings.TrimSpace(ip)) }
	}

	// HTTP/HTTPS Server Launch
	go func() {
		if *domain != "" {
			certManager := autocert.Manager{
				Prompt:     autocert.AcceptTOS,
				HostPolicy: autocert.HostWhitelist(*domain),
				Cache:      autocert.DirCache("certs-cache"),
			}
			server := &http.Server{
				Addr:    ":443",
				Handler: engine,
				TLSConfig: &tls.Config{GetCertificate: certManager.GetCertificate, MinVersion: tls.VersionTLS12},
			}
			go http.ListenAndServe(":80", certManager.HTTPHandler(nil))
			fmt.Printf("🛡️  Starting Production Secure Proxy on %s (HTTPS)\n", *domain)
			log.Fatal(server.ListenAndServeTLS("", ""))
			return
		}

		if *useHTTPS {
			lCert, lKey := "cert.crt", "cert.key"
			if _, err := os.Stat(lCert); os.IsNotExist(err) {
				crypto.GenerateSignedCert(lCert, lKey, "guardian-root.crt", "guardian-root.key")
			}
			fmt.Printf("Starting Local Secure Proxy on %s (HTTPS)\n", *listen)
			log.Fatal(http.ListenAndServeTLS(*listen, lCert, lKey, engine))
			return
		}

		fmt.Printf("Starting Proxy on %s (HTTP)\n", *listen)
		log.Fatal(http.ListenAndServe(*listen, engine))
	}()

	if *headless {
		select {}
	} else {
		themeName := "cyber"
		if cfg != nil && cfg.TUI.Theme != "" {
			themeName = cfg.TUI.Theme
		}
		p := bubbletea.NewProgram(tui.NewModel(tuiChan, engine, themeName), bubbletea.WithAltScreen())
		if _, err := p.Run(); err != nil {
			fmt.Printf("Error starting TUI: %v\n", err)
			os.Exit(1)
		}
	}
}

// rotateAndWrite handles JSON logging and automatic file rotation
func rotateAndWrite(filename string, data []byte) {
	// Max log size: 10MB
	maxSize := int64(10 * 1024 * 1024)
	
	if info, err := os.Stat(filename); err == nil {
		if info.Size() > maxSize {
			newName := fmt.Sprintf("%s.%s.bak", filename, time.Now().Format("20060102-150405"))
			os.Rename(filename, newName)
		}
	}
	
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil { return }
	defer f.Close()
	
	f.Write(data)
	f.WriteString("\n")
}
