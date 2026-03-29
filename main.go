package main

import (
	"flag"
	"fmt"
	"guardiantui/internal/proxy"
	"guardiantui/internal/tui"
	"log"
	"net/http"
	"os"

	tea "github.com/charmbracelet/bubbletea"
)

func main() {
	target := flag.String("target", "http://localhost:8080", "Target URL to protect")
	listen := flag.String("listen", ":9090", "Listen address for the proxy")
	logFile := flag.String("log", "guardian.log", "Path to the log file")
	flag.Parse()

	// Channels for fan-out
	rawLogChan := make(chan proxy.LogEntry, 100)
	tuiChan := make(chan proxy.LogEntry, 100)

	// Open log file
	f, err := os.OpenFile(*logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening log file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	// Dispatcher: File + TUI
	go func() {
		for entry := range rawLogChan {
			// Write to TUI
			tuiChan <- entry

			// Format for Sysadmin (.log)
			statusStr := "OK"
			if entry.Alert != nil {
				statusStr = fmt.Sprintf("ALERT:%s", entry.Alert.Type)
			}
			if entry.Blocked {
				statusStr = "BLOCKED"
			}

			logLine := fmt.Sprintf("[%s] %s %s %s | Status: %s | Agent: %s\n",
				entry.Timestamp.Format("2006-01-02 15:04:05"),
				entry.RemoteIP,
				entry.Method,
				entry.Path,
				statusStr,
				entry.Agent,
			)
			f.WriteString(logLine)
		}
	}()

	engine, err := proxy.NewEngine(*target, rawLogChan)
	if err != nil {
		fmt.Printf("Error starting engine: %v\n", err)
		os.Exit(1)
	}

	// Start Proxy
	go func() {
		if err := http.ListenAndServe(*listen, engine); err != nil {
			log.Fatal(err)
		}
	}()

	// Start TUI with the filtered channel
	p := tea.NewProgram(tui.NewModel(tuiChan), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error starting TUI: %v\n", err)
		os.Exit(1)
	}
}
