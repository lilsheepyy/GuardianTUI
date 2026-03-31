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
- **Transparent Proof of Work (PoW)**: Invisible, browser-based cryptographic challenge (Anti-DDoS) that stops bots without annoying CAPTCHAs.
- **Active Mitigation**: Automatically serves a 403 Forbidden page with a unique Incident ID to blocked attackers.
- **Identification & Traceability**: Injects unique headers (`X-Protected-By`, `Via`) and cookies (`guardianTUI`) for license verification and proxy identification.
- **Anonymous Telemetry**: Opt-in "Heartbeat" system to track active installations via GitHub without collecting PII or IP addresses.

---

### 🆔 Identification & Traceability
GuardianTUI identifies its traffic to both the client and the backend server using industry-standard methods:

- **🍪 Identification Cookie**: Every response includes a `guardianTUI=true` cookie.
- **🛡️ Custom Header**: The `X-Protected-By: GuardianTUI` header is added to all responses.
- **🌐 Via Header**: Follows RFC standards by adding `Via: 1.1 guardianTUI` to track the proxy chain.
- **📦 Backend Forwarding**: The `guardianTUI=true` cookie is also forwarded to your backend application, allowing your internal logic to verify that traffic is coming through the security layer.

---

### 💓 Anonymous Telemetry (Heartbeat)
To help improve the engine and track global adoption, GuardianTUI includes an **entirely anonymous** telemetry system.

- **Privacy First**: No IP addresses, User-Agents, or identifying metadata are ever sent.
- **How it Works**: A simple `GET` request is sent to a raw asset in the official GitHub repository. GitHub's internal traffic analytics count this as a "Unique Visitor."
- **Opt-in Only**: On the first run, the CLI will prompt you to enable or disable this feature. Your choice is saved in `config.yaml`.
- **Frequency**: A single "pulse" is sent every 24 hours while the engine is active.

---

### 🚨 Zero Tolerance: Anti-CSAM Shield
GuardianTUI incorporates a specialized **Illicit Content Shield** designed to identify and block requests related to child sexual abuse material (CSAM).

- **🧠 Heuristic Scoring Engine**: Beyond simple keywords, it uses a multi-layered scoring system that analyzes combinations of terms and context.
- **🔄 Advanced Normalization**: Bypasses attempts to hide illicit terms using leetspeak (e.g., `@` for `a`, `4` for `a`), Base64, or Hex encoding.
- **🚨 Priority Scanning**: This check runs with **absolute priority** before any other security analysis, ensuring zero tolerance for illicit content.
- **🤖 Integrated AI Safety**: Deep integration with the **AI Shield** to detect and block attempts to generate, describe, or roleplay illicit content via LLMs.
- **📊 Detailed Alerts**: Incidents are flagged specifically as `ZERO TOLERANCE: CSAM Shield` in the TUI and logs for immediate forensic awareness.

---

### 💣 Metasploit & Exploit Shield
Advanced protection against common exploitation frameworks and automated attack tools.

- **🕵️ Meterpreter Detection**: Identifies Meterpreter HTTP/HTTPS transport patterns, including Payload UUIDs and session polling strings (`RECV`).
- **🧮 URI Checksum Heuristics**: Implements the Metasploit 8-bit checksum algorithm to identify stagers (Windows, Java, Python, PHP) even with randomized alphanumeric URIs.
- **🐚 PowerShell Stager Defense**: Blocks common "One-Liner" download/execute stagers used by `web_delivery` and other MSF modules.
- **🛠️ Generic Exploit Mitigation**: Generic signatures for critical vulnerability classes like **Log4j (JNDI)**, **Struts2 (OGNL)**, and Java deserialization attacks.
- **📦 Modular Architecture**: Logic is isolated in a dedicated `metasploit` package for high-performance inspection.

---

### 🐚 Reverse Shell Shield
Real-time detection of TCP/UDP reverse shell one-liners and socket redirection payloads.

- **🖥️ Multi-Language Support**: Signatures for Bash, Python, Perl, PHP, Ruby, and Lua reverse shells.
- **🛡️ Socket Defense**: Identifies common `/dev/tcp` and `/dev/udp` redirections.
- **🔧 Netcat Mitigation**: Detects Netcat execution flags (`-e`, `-c`) and FIFO backpipe shell patterns.
- **⚡ Zero-Latency Filtering**: Pre-compiled regex patterns ensure no performance impact during deep packet inspection.


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
Manage high-threat actors through local files or remote URLs. **GuardianTUI automatically refreshes these lists every 1 minute** and performs an immediate update upon startup.

#### Active Threat Feeds (Configured by Default):
- **🔥 FireHOL Proxies**: Comprehensive aggregate of open proxies detected in the last 30 days.
- **🛡️ Spamhaus DROP**: "Do Not Route Or Peer" list containing hijacked or malicious network blocks.
- **🛑 AbuseIPDB**: Highly reported IPs with 100% confidence level for recent malicious activity.
- **🔐 SSL Proxies**: A frequently updated feed of active open SSL proxies used for anonymization.

```yaml
# Path to an external file with IPs/CIDRs to block (one per line)
blocklist_path: "blocklist.txt"

# Remote blocklist URLs (Refreshed every 60 seconds)
remote_blocklists:
  - "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/sslproxies_7d.ipset"
  - "https://raw.githubusercontent.com/firehol/blocklist-ipsets/refs/heads/master/firehol_proxies.netset"
  - "https://www.spamhaus.org/drop/drop.txt"
  - "https://raw.githubusercontent.com/borestad/blocklist-abuseipdb/main/abuseipdb-s100-1d.ipv4"
```

#### Local Cache & Sanitization
GuardianTUI maintains a **Local Persistent Cache** in the `proxylistblock/` folder:
- **Automatic Sanitization**: All lists are stripped of headers, comments (`;` or `#`), and metadata descriptions.
- **Clean Storage**: Files like `spamhaus_drop.txt` and `abuseipdb.txt` are stored as pure IP/CIDR lists for easy audit.
- **No Latency**: The engine performs a full update in the background every minute without interrupting active traffic filtering.

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
