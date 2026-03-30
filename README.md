# 🛡️ GuardianTUI: High-Performance L7 IPS & AI Shield

[![Go Report Card](https://goreportcard.com/badge/github.com/lilsheepyy/GuardianTUI)](https://goreportcard.com/report/github.com/lilsheepyy/GuardianTUI)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go 1.21+](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org/dl/)

**GuardianTUI** is a professional-grade **L7 Reverse Proxy & Intrusion Prevention System (IPS)** designed for the AI era. It protects web applications and AI APIs from sophisticated attacks using a **Heuristic Scoring Engine**, **Recursive Normalization**, and a real-time **TUI Dashboard**.

---

## 🚀 Quick Start

### Build
```bash
go build -o guardiantui main.go
```

### Basic Run
Proxy traffic from port 8080 to your local app on port 3000:
```bash
./guardiantui -target http://localhost:3000
```

---

## 🛠️ Command Line Interface

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-target` | The backend URL you want to protect | `http://localhost:80` |
| `-listen` | Address and port to listen on | `:8080` |
| `-config` | Path to the YAML security configuration | `config.yaml` |
| `-ai-rules` | Path to the custom AI detection rules (JSON) | `ai.json` |
| `-log` | Path to the persistent attack log file | `guardian.log` |
| `-whitelist` | Comma-separated IPs/CIDRs to bypass checks | `""` |
| `-https` | Enable local HTTPS with self-signed certs | `false` |
| `-domain` | Enable Production SSL via Let's Encrypt (ACME) | `""` |

### Usage Examples

**1. Production Mode (Auto SSL):**
Automatically provision and renew certificates for your domain:
```bash
sudo ./guardiantui -target http://localhost:3000 -domain example.com
```

**2. Local Secure Proxy (Self-signed):**
Test HTTPS locally on a specific port:
```bash
./guardiantui -target http://localhost:3000 -listen :443 -https
```

**3. Specific Whitelisting:**
Allow your internal network or a specific IP to bypass the security engine:
```bash
./guardiantui -target http://localhost:3000 -whitelist 192.168.1.0/24,10.0.0.5
```

**4. Custom Security Policies:**
Run with a specific configuration for a staging environment:
```bash
./guardiantui -config staging-config.yaml -ai-rules staging-ai.json
```

---

## 🤖 Exclusive: AI Shield (Anti-AI Abuse)

### Advanced AI Protection
Define your AI endpoints in `config.yaml`:
```yaml
ai_protection:
  endpoints: ["/v1/chat"]
  score_threshold: 5
```

---

## 🛡️ Network Defense

### User-Agent & IP Blocklists
Manage threat actors efficiently through `config.yaml`:

```yaml
# List of User-Agent substrings to block automatically
blocked_user_agents:
  - "CensysInspect"
  - "zgrab"

# Path to an external file with IPs/CIDRs to block (one per line)
blocklist_path: "blocklist.txt"
```

The `blocklist.txt` file supports single IPs and CIDR ranges:
```text
# Block list example
185.93.89.43
192.168.100.0/24
```

---

## ⌨️ TUI Shortcuts

| Key | Action |
| :--- | :--- |
| `q` / `Ctrl+C` | Quit |
| `/` | **Search Mode**: Filter logs by ID, IP, or Attack Type |
| `Esc` | Clear filter or exit search |
| `↑` / `↓` | Scroll through request history |

---

## 📝 Forensics & Logs
Detailed reports in `guardian.log` with unique incident IDs for easy auditing:
```log
[2026-03-29 23:51:43] ID:b6e91bc4 IP:1.2.3.4 POST /v1/chat | Status:BLOCKED:AI Abuse | Agent:python-requests/2.31
  ↳ [DETECTION] Type:AI Abuse: High Suspect Score (7) | Patterns: Instruction Override, Persona Hijack
```

---

## 🏷️ SEO & Metadata
#Cybersecurity #WAF #IPS #LLMSecurity #PromptInjection #JailbreakDefense #Golang #APIProtection #InfoSec #OpenSource #DevSecOps #AIGovernance #TerminalUI

---

## 📜 License
Distributed under the **MIT License**.
