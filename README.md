# 🛡️ GuardianTUI: High-Performance L7 IPS & AI Shield

[![Go Report Card](https://goreportcard.com/badge/github.com/lilsheepyy/GuardianTUI)](https://goreportcard.com/report/github.com/lilsheepyy/GuardianTUI)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go 1.21+](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org/dl/)

**GuardianTUI** is a professional-grade **L7 Reverse Proxy & Intrusion Prevention System (IPS)** designed for the AI era. It protects web applications and AI APIs from sophisticated attacks using a **Heuristic Scoring Engine**, **Recursive Normalization**, and a real-time **TUI Dashboard**.

---

## 🤖 Exclusive: AI Shield (Anti-AI Abuse)
GuardianTUI features a specialized defense layer for Large Language Models (LLMs) and Generative AI APIs. It goes beyond simple keyword matching to understand **malicious intent**.

- **🧠 Heuristic Scoring**: Detects **Prompt Injection** and **Jailbreak** attempts (DAN, Developer Mode, Virtualization) by calculating a suspect score based on semantic patterns.
- **🚫 PII Leakage Protection**: Automatically scans and blocks sensitive data (Credit Cards, SSN) before they reach your AI model.
- **🛡️ Instruction Override Defense**: Blocks attempts to bypass system prompts (e.g., "ignore all previous instructions").
- **🧩 Structural Hijacking Detection**: Identifies attempts to inject system-level delimiters (`Assistant:`, `System:`) to manipulate model behavior.

---

## 🚀 Key Features

- **🔄 Recursive Normalization Engine**: Automatically decodes up to 3 layers of obfuscation (**Base64, Hex, Double URL Encoding, HTML Entities**).
- **🛡️ Active Blocking**: Intercepts threats and serves a professional HTML block page with a unique **Incident ID**.
- **📊 Real-time TUI Chart**: High-performance terminal dashboard with live traffic activity and threat charts.
- **🔍 360° Inspection**: Deep packet inspection of **Headers, Cookies, Query Parameters, and Body** (up to 1MB).
- **⚙️ Fully Configurable**: Control every threshold, window, and security rule via `config.yaml` and `ai.json`.
- **🌐 Zero-Config HTTPS**: Automated SSL provisioning via **Let's Encrypt** or custom/self-signed certificates.

---

## 🛠️ Quick Start

### Build & Run
```bash
go build -o guardiantui main.go
./guardiantui -target http://localhost:3000
```

### Advanced AI Protection
Define your AI endpoints in `config.yaml`:
```yaml
ai_protection:
  endpoints: ["/v1/chat"]
  score_threshold: 5
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
