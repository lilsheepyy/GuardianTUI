package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"guardiantui/internal/proxy"
	"guardiantui/internal/tui"
	"guardiantui/internal/crypto"
	"guardiantui/internal/scanner"
	"log"
	"net/http"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	target := flag.String("target", "http://localhost:80", "Target URL to protect")
	listen := flag.String("listen", ":8080", "Listen address for the proxy")
	logFile := flag.String("log", "guardian.log", "Path to the log file")
	configFile := flag.String("config", "config.yaml", "Path to the YAML config file")
	aiRulesFile := flag.String("ai-rules", "ai.json", "Path to the AI custom rules JSON file")
	
	domain := flag.String("domain", "", "Auto-provision real Let's Encrypt SSL for this domain")
	whitelistFlag := flag.String("whitelist", "", "Comma-separated list of IPs or CIDR ranges to whitelist")
	useHTTPS := flag.Bool("https", false, "Enable local self-signed HTTPS mode")
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

	f, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening log file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	go func() {
		for entry := range rawLogChan {
			tuiChan <- entry
			statusStr := "OK"
			if entry.Alert != nil { statusStr = fmt.Sprintf("ALERT:%s", entry.Alert.Type) }
			if entry.Blocked { statusStr = "BLOCKED" }
			logLine := fmt.Sprintf("[%s] ID:%s IP:%s %s %s | Status:%s | Agent:%s\n",
				entry.Timestamp.Format("2006-01-02 15:04:05"), entry.ID, entry.RemoteIP, entry.Method, entry.Path, statusStr, entry.Agent)
			f.WriteString(logLine)
		}
	}()

	engine, err := proxy.NewEngine(*target, rawLogChan, cfg)
	if err != nil {
		fmt.Printf("Error starting engine: %v\n", err)
		os.Exit(1)
	}

	if cfg != nil {
		for _, ip := range cfg.Whitelist { engine.AddWhitelist(ip) }
	}

	// Initial update before starting the ticker
	engine.UpdateBlocklists()
	engine.StartAutoUpdate()

	if *whitelistFlag != "" {
		ips := strings.Split(*whitelistFlag, ",")
		for _, ip := range ips { engine.AddWhitelist(strings.TrimSpace(ip)) }
	}

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

	p := tea.NewProgram(tui.NewModel(tuiChan), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error starting TUI: %v\n", err)
		os.Exit(1)
	}
}
