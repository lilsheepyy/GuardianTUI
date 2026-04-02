# 🛡️ GuardianTUI

![Active Instances](https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https://github.com/lilsheepyy/GuardianTUI/active-instances&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23E7E7E7&title=Active+Instances&edge_flat=false)
![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)
![License](https://img.shields.io/badge/License-MIT-green.svg)

**GuardianTUI** is an ultra-high performance **L7 Reverse Proxy & Intrusion Prevention System (IPS)** written in Go. It provides real-time threat detection, automated blocking, and a high-performance **v2.0 Terminal Dashboard** for mission-critical monitoring.

---

## 📑 Deep Documentation (Wiki)
For a detailed dive into how GuardianTUI works, please refer to our documentation:

- 🏛️ **[Architecture & Internals](./docs/ARCHITECTURE.md)**: Sharding, Atomic Pointer Swapping, and PoW logic.
- 📡 **[Security Shields](./docs/SECURITY_ENGINE.md)**: CSAM, Metasploit, Reverse Shell, DLP, and Offensive Tooling shields.
- ⚙️ **[Configuration Guide](./docs/CONFIGURATION.md)**: Full guide for `config.yaml`, `ai.json`, and IP Blocklists.
- 📊 **[Dashboard & TUI Guide](./docs/DASHBOARD_GUIDE.md)**: Deep dive into the v2.0 metrics and controls.

---

## ⚡ Quick Start

### 1. Build from Source
```bash
git clone https://github.com/lilsheepyy/GuardianTUI.git
cd GuardianTUI
go build -o guardiantui main.go
```

### 2. Protect an Application
Protect a local application running on port 3000:
```bash
./guardiantui -target http://localhost:3000
```
Your application is now filtered and accessible via `http://localhost:8080`.

---

## 🚀 Key Features

- **High-Performance Sharding**: 64-way memory sharding for IP tracking and probing detection.
- **Lock-Free Snapshots**: Atomic pointer swapping for zero-latency security updates.
- **Deep Packet Inspection**: Recursive normalization (Base64, Hex, URL, HTML) of payloads.
- **Advanced AI Shield**: Heuristic scoring specifically optimized for LLM/AI endpoints.
- **Enterprise Logging**: Persistent JSON logging with automatic 10MB file rotation in the `logs/` folder.
- **Network Hardening**: Integrated Cloudflare (`CF-Connecting-IP`) support and a strict Unauthorized Proxy Shield.
- **DLP Engine**: Inbound file protection and outbound secret redaction.
- **v2.0 Dashboard**: Modern, responsive TUI with traffic heatmaps and threat distribution charts.
- **Dynamic Operational Modes**: Switch between `IPS` (Active), `IDS` (Passive/Logging), and `Strict` modes via configuration or TUI.
- **Custom TUI Themes**: Multiple visual styles (Cyber, Forest, Dracula, Monochrome) selectable via configuration or TUI command.

---

## 🛠️ Operational Modes

- **Production Mode (SSL)**: `sudo ./guardiantui -target http://localhost:3000 -domain example.com`
- **Local Secure Mode**: `./guardiantui -target http://localhost:3000 -https`
- **Headless Mode**: `./guardiantui -target http://localhost:3000 -headless`

---

## 📜 License
Distributed under the **MIT License**. Created by **sheep**.
