# 🛡️ GuardianTUI: High-Performance L7 IPS & Real-Time Network Security Dashboard

[![Go Report Card](https://goreportcard.com/badge/github.com/lilsheepyy/GuardianTUI)](https://goreportcard.com/report/github.com/lilsheepyy/GuardianTUI)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go 1.21+](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org/dl/)

**GuardianTUI** is a carrier-grade, open-source **Intrusion Prevention System (IPS)** and **L7 Reverse Proxy** built for extreme speed, security, and visibility. Powered by a **Sharded Thread-Safe Engine** in Go, it protects your applications against modern threats while providing a real-time **TUI (Terminal User Interface)**.

---

## 🚀 Why GuardianTUI?

- **🛡️ Active L7 Firewall**: Deep Packet Inspection (DPI) to block SQLi, XSS, RCE, and more.
- **🍪 Deep Cookie Inspection**: Scans every cookie value for hidden malicious payloads.
- **📊 Live TUI Dashboard**: Monitor every request and threat as they happen in your terminal.
- **⚡ Sharded Architecture**: Uses 64 concurrent shards to eliminate lock contention, ensuring ultra-low latency under heavy load.
- **🔍 Forensic-Ready Logs**: Detailed incident reports with unique IDs, full headers, and payload samples.

---

## ✨ Advanced Detection Capabilities

GuardianTUI identifies and mitigates a wide range of threats:

### 1. OWASP Top 10 & Payload Attacks
- **SQL Injection (SQLi)**: Detects classic, blind, and evasion-based SQL injections.
- **Cross-Site Scripting (XSS)**: Identifies script tags, event handlers, and javascript: pseudo-protocols.
- **Remote Code Execution (RCE)**: Blocks command injections (`system`, `exec`, `shell_exec`, etc.).
- **Path Traversal / LFI / RFI**: Prevents access to sensitive system files like `/etc/passwd`.

### 2. Bot & Scanner Fingerprinting (40+ Signatures)
- **Security Scanners**: Acunetix, Nessus, Qualys, Netsparker, OpenVAS, Arachni.
- **Pentest Tools**: nmap, sqlmap, nuclei, nikto, ffuf, gobuster, dirsearch, feroxbuster.
- **Aggressive Bots**: Shodan, Censys, MJ12bot, AhrefsBot, SemrushBot.
- **Technical Headers**: Detects tools via specific headers like `X-Scanner`, `X-Bug-Bounty`, and `X-Scan-ID`.

### 3. Stateful Protection
- **Anti-DoS / Brute Force**: Tracks request rates per IP using a high-performance sharded tracker.
- **Sensitive Data Shield**: Blocks attempts to reach `.env`, `.git`, `.aws/credentials`, and WP-config files.

---

## 🛠️ Installation & Quick Start

### Build from Source
```bash
git clone https://github.com/lilsheepyy/GuardianTUI.git
cd GuardianTUI
go build -o guardiantui main.go
```

### Protect your API
```bash
./guardiantui -listen :9090 -target http://localhost:8080
```

---

## 📝 Forensic Logging (Admin-Ready)

Detailed reports in `guardian.log`:
```log
[2026-03-29 16:45:10] ID:a1b2c3d4 IP:1.2.3.4 POST /api/v1/upload | Status:ALERT:Command Injection | Agent:curl/8.1.2
  ↳ [DETECTION] Type:Command Injection | Pattern:(?i)(exec|system|shell_exec|eval)
  ↳ [PAYLOAD] {"file": "test.txt", "cmd": "rm -rf /; id"}
```

---

## 🏷️ Tags & SEO
#CyberSecurity #Golang #IDS #IPS #Networking #OpenSource #DevSecOps #InfoSec #L7Firewall #TUI #ReverseProxy #OWASP #ThreatDetection #SecurityMonitoring #AntiBot #WAF

---

## 📜 License
Distributed under the **MIT License**.
