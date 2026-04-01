# 🛡️ GuardianTUI v2.0 | Advanced L7 IPS & Reverse Proxy

![Active Instances](https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https://github.com/lilsheepyy/GuardianTUI/active-instances&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23E7E7E7&title=Active+Instances&edge_flat=false)
![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/License-MIT-green.svg)

**GuardianTUI** is an ultra-high performance **L7 Reverse Proxy & Intrusion Prevention System (IPS)** designed for modern web applications and AI-driven endpoints. Version 2.0 introduces a completely overhauled **Cyber-Security Dashboard**, sharded memory management for extreme throughput, and lock-free security snapshots.

---

## 📑 Table of Contents
1. [Core Architecture](#-core-architecture)
2. [Installation & Building](#-installation--building)
3. [Quick Start](#-quick-start)
4. [Configuration Guide](#-configuration-guide)
    - [YAML Security Engine](#-yaml-security-engine)
    - [Custom AI Heuristics](#-custom-ai-heuristics)
5. [Network Defense](#-network-defense)
    - [User-Agent Blocking](#-user-agent-blocking)
    - [IP Blocklists](#-ip-blocklists)
6. [Operational Modes](#-operational-modes)
7. [TUI Dashboard Guide (v2.0)](#-tui-dashboard-guide-v20)
8. [Forensics & Logs](#-forensics--logs)

---

## 🏛️ Core Architecture

GuardianTUI operates as a transparent, high-speed security layer.

- **🚀 Sharded Memory Management**: Uses 64-way memory sharding for IP tracking and probing detection to minimize lock contention on high-traffic servers.
- **⚡ Lock-Free Security Snapshots**: Blocklists and subnets are managed via `atomic.Pointer` snapshots, allowing zero-latency lookups during active traffic filtering.
- **Recursive Normalization**: Decodes up to 3 layers of obfuscation (Base64, Hex, Double URL Encoding, HTML Entities) before analysis.
- **Heuristic Scoring Engine**: Calculates a "Threat Score" for incoming requests, specifically optimized for LLM/AI prompts.
- **Transparent Proof of Work (PoW)**: Invisible, browser-based cryptographic challenge (Anti-DDoS) that stops bots without annoying CAPTCHAs.
- **Active Mitigation**: Automatically serves a 403 Forbidden page with a unique Incident ID to blocked attackers.
- **Anonymous Telemetry**: Opt-in "Heartbeat" system to track active installations via GitHub without collecting PII or IP addresses.

---

### 📦 DLP Shield (Data Loss Prevention)
A dedicated package (`internal/scanner/dlp`) designed to prevent information disclosure both inbound and outbound.

- **🛡️ Inbound Protection**: Automatically blocks requests for sensitive files like `.env`, `.git/`, SSH private keys (`id_rsa`), and configuration files.
- **🛡️ Outbound Redaction**: Intercepts text-based response bodies and automatically redacts leaked secrets (AWS Keys, GitHub Tokens, Database Strings, JWTs) with `[REDACTED SECRET]`.

---

### 📡 Offensive Tooling & Framework Shields
GuardianTUI is pre-configured to detect and block the most common offensive security frameworks and scanners.

- **🗺️ Nmap Shield**: Blocks **Nmap Scripting Engine (NSE)** probes, identifying specific payloads like `http-sql-injection` and `http-enum`.
- **🧪 Nuclei & Template Scanning**: Detects OAST interaction domains (Interactsh, Oastify, Oast.pro) and Nuclei-specific headers.
- **☕ Burp Suite Defense**: Identifies Burp Collaborator payloads and intruder/spidering patterns.
- **🐝 BeEF Framework**: Specifically blocks the Browser Exploitation Framework by targeting `hook.js` and common panel endpoints.
- **🔥 Log4j / JNDI / OGNL**: Protects against remote code execution via `${jndi:ldap...}` and expression language injections.

---

## 📊 TUI Dashboard Guide (v2.0)

The **GuardianTUI v2.0 Dashboard** is a high-performance monitoring interface built for full-size terminals with adaptive resizing support.

### 📈 Mission Control Panes
- **Live Activity Heatmap**: A high-resolution 60-second traffic chart showing the ratio of "Safe" (Green) vs. "Threat" (Red) traffic.
- **Threat Distribution Bar Chart**: Automatically ranks and visualizes the top 5 attack categories (e.g., SQLi, XSS, Path Traversal) by frequency.
- **Metric Summary Bar**: Real-time display of **Uptime**, **Total Requests**, **Total IPS Blocks**, and current **RPS (Requests Per Second)**.

### ⌨️ Interactive Controls
- **Search Mode (`/`)**: Dynamically filter logs by IP, Incident ID, Status, or Path.
- **Critical Alert Line**: A bold, color-coded status bar that turns Red during active incidents and provides immediate forensic context for the latest block.
- **Responsive Layout**: The dashboard automatically switches between side-by-side and stacked views based on terminal width.

---

## 🔨 Installation & Building

### Prerequisites
- **Go 1.21** or higher.
- Linux/macOS/Windows (TUI optimized for Unix-like terminals).

### Build from Source
```bash
git clone https://github.com/lilsheepyy/GuardianTUI.git
cd GuardianTUI
go build -o guardiantui main.go
```

---

## 🚀 Quick Start

Protect a local application running on port 3000:
```bash
./guardiantui -target http://localhost:3000
```
On the first run, you will be prompted to enable/disable anonymous telemetry. Access your application through `http://localhost:8080`.

---

## ⚙️ Configuration Guide

### 📄 YAML Security Engine (`config.yaml`)
```yaml
engine:
  max_scan_size_bytes: 1048576       # Scan up to 1MB of payload
  probing_window_seconds: 60         # Time window to track suspicious IPs
  probing_threshold_unique: 3        # Block if 3+ unique attack types detected
  spam_threshold_total: 5            # Block if 5+ attacks of any type detected

ai_protection:
  endpoints: ["/v1/chat", "/api"]    # Endpoints requiring AI heuristics
  score_threshold: 5                 # Stricter if lower (default 5)
  protect_pii: true                  # Block Credit Cards/SSNs in prompts
  blocked_keywords:                  # Instant block for these words
    - "internal_key"
    - "admin_password"

whitelist:
  - "127.0.0.1"                      # Your own IP to avoid self-blocking
  - "192.168.1.0/24"                 # Trusted local network
```

---

## 📝 Forensics & Logs

Every block event is recorded in `guardian.log` with a structured format:

```log
[2026-03-31 14:20:05] ID:e6b8a1 ID IP:1.2.3.4 POST /v1/chat | Status:BLOCKED:SQL Injection | Agent:Mozilla/5.0...
```

The **Incident ID** matches the ID displayed on the block page for quick forensic correlation.

---

## 📜 License
Distributed under the **MIT License**. Created by **sheep**.
