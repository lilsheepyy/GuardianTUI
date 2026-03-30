# 🛡️ GuardianTUI User Manual & Documentation

**GuardianTUI** is an advanced **L7 Reverse Proxy & Intrusion Prevention System (IPS)** written in Go. It provides real-time threat detection, automated blocking, and a high-performance Terminal User Interface (TUI) for monitoring.

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
7. [TUI Dashboard Guide](#-tui-dashboard-guide)
8. [Forensics & Logs](#-forensics--logs)

---

## 🏛️ Core Architecture

GuardianTUI operates as a transparent layer between the internet and your application.

- **Recursive Normalization**: Decodes up to 3 layers of obfuscation (Base64, Hex, Double URL Encoding, HTML Entities) before analysis.
- **Heuristic Scoring Engine**: Calculates a "Threat Score" for incoming requests, specifically optimized for LLM/AI prompts.
- **Sharded Probing Detection**: Uses high-performance memory sharding to track "Probing Bots" that test multiple vulnerabilities over time.
- **Active Mitigation**: Automatically serves a 403 Forbidden page with a unique Incident ID to blocked attackers.

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
Access your app through `http://localhost:8080` (default proxy port).

---

## ⚙️ Configuration Guide

### 📄 YAML Security Engine (`config.yaml`)
The main configuration file controls the intensity of the security engine.

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
```

### 🧠 Custom AI Heuristics (`ai.json`)
Define your own weights for specific prompt patterns.

```json
[
  {
    "pattern": "(?i)reveal your secret key",
    "weight": 5,
    "description": "Custom Secret Key Leakage"
  },
  {
    "pattern": "(?i)ignore instructions",
    "weight": 3,
    "description": "Override Attempt"
  }
]
```
If the cumulative weight of matched patterns reaches the `score_threshold`, the request is blocked.

---

## 🛡️ Network Defense

### 🕵️ User-Agent Blocking
Block automated scanners by their signature in `config.yaml`:
```yaml
blocked_user_agents:
  - "CensysInspect"
  - "Go-http-client"
  - "zgrab"
  - "sqlmap"
```

### 🚫 IP Blocklists
Maintain a dynamic list of bad actors in `blocklist.txt` (specified by `blocklist_path` in config).
- **Format**: One IP or CIDR per line.
- **Example**:
  ```text
  1.2.3.4
  192.168.1.0/24
  # This is a comment
  45.76.181.67
  ```

---

## 🌐 Operational Modes

### 1. Production Mode (HTTPS via Let's Encrypt)
GuardianTUI can automatically manage SSL certificates.
```bash
sudo ./guardiantui -target http://localhost:3000 -domain example.com
```

### 2. Local Secure Mode (Self-signed)
Useful for testing HTTPS features locally.
```bash
./guardiantui -target http://localhost:3000 -https -listen :443
```

### 3. Custom Ports & Logging
```bash
./guardiantui -target http://localhost:3000 -listen :9000 -log security.log
```

---

## 📊 TUI Dashboard Guide

The Terminal interface is your live mission control:

- **Live Log Feed**: Shows real-time requests. Red entries indicate blocked threats.
- **Traffic Stats**: Breakdown of allowed vs. blocked traffic.
- **Threat Chart**: Visualizes attack frequency over time.
- **Search Mode (`/`)**: Type any string (IP, ID, or Type) to filter logs instantly.
- **Navigation**: Use arrow keys to scroll through the history of captured attacks.

---

## 📝 Forensics & Logs

Every block event is recorded in `guardian.log` with a structured format:

```log
[2026-03-31 14:20:05] ID:e6b8a1 ID IP:1.2.3.4 POST /v1/chat | Status:BLOCKED:AI Abuse | Agent:Mozilla/5.0...
```

The **Incident ID** shown in the log matches the ID displayed to the user on the block page, allowing you to quickly find the exact request that triggered a block when a user reports a false positive.

---

## 📜 License
Distributed under the **MIT License**. Created by **sheep**.
