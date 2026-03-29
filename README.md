# 🛡️ GuardianTUI

**GuardianTUI** is a High-Performance, Real-Time L7 Intrusion Prevention System (IPS) and Reverse Proxy written in pure Go. It features a modern Terminal User Interface (TUI) and comprehensive logging, designed for sysadmins and security professionals to monitor, detect, and block malicious HTTP traffic on the fly.

## ✨ Features
- **Real-Time TUI**: Built with Bubble Tea, offering a live dashboard of incoming traffic and alerts.
- **Advanced Threat Detection Engine**:
  - SQL Injection (SQLi) & Evasions
  - Cross-Site Scripting (XSS)
  - Local/Remote File Inclusion (LFI/RFI)
  - Command Injection & Remote Code Execution (RCE)
  - Path Traversal & Sensitive File Exposure (`.env`, `.git`, etc.)
  - Malicious Scanner & Bot Detection (nmap, sqlmap, nuclei, burpsuite)
  - Stateful Rate Limiting & DoS / Brute Force Protection
- **Sysadmin Friendly Logging**: Outputs clean, parseable logs to `guardian.log` for easy integration with SIEMs or Fail2Ban.
- **Instant Blocking**: Intercept and drop malicious requests instantly.
- **Zero Dependencies**: Distributed as a single static binary.

## 🚀 Installation

Ensure you have Go 1.21+ installed.

```bash
git clone https://github.com/lilsheepyy/GuardianTUI.git
cd GuardianTUI
go build -o guardiantui main.go
```

## 🛠️ Usage

Wrap your existing backend application with GuardianTUI to instantly protect it:

```bash
./guardiantui -listen :9090 -target http://localhost:8080
```
- `-listen`: Address and port for GuardianTUI to bind to (default: `:9090`)
- `-target`: The backend URL you want to protect (default: `http://localhost:8080`)
- `-log`: Path to the log file (default: `guardian.log`)

### TUI Controls
- `q` or `ctrl+c`: Quit the application
- `b`: Block the currently selected IP
- `Up/Down Arrows`: Scroll through the live traffic log

## 📝 Log Format
Logs are written in a structured format suitable for grepping or ingestion:
```
[YYYY-MM-DD HH:MM:SS] <IP> <METHOD> <PATH> | Status: <STATUS> | Agent: <USER_AGENT>
```

**Example:**
```log
[2026-03-29 16:11:05] 10.0.0.5 POST /login | Status: OK | Agent: Mozilla/5.0
[2026-03-29 16:11:12] 192.168.1.15 GET /?id=1' OR '1'='1' | Status: ALERT:SQL Injection | Agent: sqlmap/1.8.3
[2026-03-29 16:12:00] 192.168.1.15 GET /?id=1' OR '1'='1' | Status: BLOCKED | Agent: sqlmap/1.8.3
```

## 🤝 Contributing
Contributions, issues, and feature requests are welcome!

## 📜 License
MIT License
