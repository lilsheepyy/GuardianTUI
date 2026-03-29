# 🛡️ GuardianTUI: High-Performance L7 IPS & Real-Time Network Security Dashboard

[![Go Report Card](https://goreportcard.com/badge/github.com/lilsheepyy/GuardianTUI)](https://goreportcard.com/report/github.com/lilsheepyy/GuardianTUI)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go 1.21+](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org/dl/)

**GuardianTUI** is a carrier-grade, open-source **Intrusion Prevention System (IPS)** and **L7 Reverse Proxy** built for speed, security, and visibility. Powered by a high-performance sharded engine in Go, it protects your backend applications against the **OWASP Top 10** while providing a beautiful, real-time **TUI (Terminal User Interface)** for security monitoring.

---

## 🚀 Why GuardianTUI?

In an era of automated attacks, static logs aren't enough. GuardianTUI gives you **active defense** and **instant visibility**. 

- **🛡️ Active L7 Firewall**: Deep Packet Inspection (DPI) to block SQLi, XSS, RCE, and more.
- **📊 Live TUI Dashboard**: Monitor every request and threat as they happen, right from your terminal.
- **🧠 Intelligent Threat Detection**: Signature-based and stateful heuristic analysis.
- **⚡ Ultra-Low Latency**: Built in Go for high-throughput environments.
- **🔍 Forensic-Ready Logs**: Detailed incident reports with unique IDs, full headers, and payload samples.

---

## ✨ Advanced Security Features

- **OWASP Protection**: Battle-tested regex patterns for SQL Injection, XSS, Path Traversal, and Command Injection.
- **Bot & Scanner Mitigation**: Passive detection of tools like `sqlmap`, `nmap`, `nuclei`, `dirbuster`, and `burpsuite`.
- **Stateful Rate Limiting**: Automatic detection of **DoS / Brute Force** attacks via sliding window analysis.
- **Sensitive Data Shield**: Prevents unauthorized access to `.env`, `.git`, AWS credentials, and configuration files.
- **One-Click Banning**: Instant manual IP blocking via the TUI.

---

## 🛠️ Installation & Quick Start

### 1. Build from Source
```bash
git clone https://github.com/lilsheepyy/GuardianTUI.git
cd GuardianTUI
go build -o guardiantui main.go
```

### 2. Protect your API
```bash
./guardiantui -listen :9090 -target http://localhost:8080
```

---

## 📝 Forensic Logging (Admin-Ready)

GuardianTUI generates highly detailed logs in `guardian.log`, perfect for sysadmins and security auditors:

```log
[2026-03-29 16:11:12] ID:8f2a1c4b IP:192.168.1.15 GET /api/v1?id=1' OR '1'='1' | Status:ALERT:SQL Injection | Agent:sqlmap/1.8.3
  ↳ [DETECTION] Type:SQL Injection | Pattern:(?i)(union|select|drop|insert|truncate|delete|1=1|' OR '1'='1')
  ↳ [PAYLOAD] id=1' OR '1'='1'
```

---

## ⌨️ TUI Keybindings

| Key | Action |
| :--- | :--- |
| `q` / `Ctrl+C` | Quit GuardianTUI |
| `b` | **Block** the selected IP address instantly |
| `↑` / `↓` | Scroll through the request history |

---

## 🏷️ Tags & SEO
#CyberSecurity #Golang #IDS #IPS #Networking #OpenSource #DevSecOps #InfoSec #L7Firewall #TUI #ReverseProxy #OWASP #ThreatDetection #SecurityMonitoring

---

## 📜 License
Distributed under the **MIT License**. See `LICENSE` for more information.

**Keywords**: *L7 IPS, Go Security Tool, Terminal Dashboard, Network Intrusion Prevention, DDoS Mitigation, Real-time Traffic Monitoring, Golang Firewall.*
