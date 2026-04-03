# 📡 Security Shields & Offensive Tooling Defense

GuardianTUI is equipped with an industry-leading suite of security shields designed to identify, block, and log sophisticated attack vectors.

---

## 🚨 Zero Tolerance: Anti-CSAM Shield
A specialized **Illicit Content Shield** that runs with absolute priority.
- **🧠 Heuristic Analysis**: Beyond simple keyword matching, it analyzes term combinations and context.
- **🔄 Obfuscation Bypass**: Detects attempts to hide illicit terms using leetspeak, Base64, or Hex encoding.

---

## 💣 Exploit & Overflow Shield (Memory Defense)
Protection against binary exploitation and memory-based attacks.
- **🛡️ NOP Sled Detection**: Identifies long sequences of `\x90` or `0x90` used to "slide" execution into shellcode.
- **🛡️ Buffer Overflow Heuristics**: Detects unusually long repetitive strings (e.g., `AAAA...`) and format string attacks (`%n`, `%p`).
- **🛡️ Shellcode Detection**: Identifies common raw byte-code patterns typically found in exploit payloads.

---

## 💣 Metasploit Shield
- **🕵️ Meterpreter Detection**: Identifies Meterpreter transport patterns and session polling strings.
- **🧮 URI Checksum Heuristics**: Implements the Metasploit 8-bit checksum algorithm to block alphanumeric stagers even when URIs appear random.

---

## 🐚 RCE & Reverse Shell Shield
Real-time detection of system discovery and interactive shell established attempts.
- **🖥️ Command Injection**: Detects discovery commands like `whoami`, `id`, `ls`, and `ifconfig` when triggered via shell separators (`;`, `|`, `&&`).
- **🖥️ Execution Wrappers**: Blocks backtick (`` `cmd` ``) and subshell (`$(cmd)`) execution attempts.
- **🖥️ Interactive Shells**: Support for Bash, Python, Perl, and Netcat reverse shell one-liner patterns.

---

## 📊 SQL Injection Shield (Deep Heuristics)
Advanced detection for all major databases (MySQL, PostgreSQL, MSSQL, SQLite).
- **🛡️ Time-Based Blind SQLi**: Detects payloads using `pg_sleep()`, `benchmark()`, `WAITFOR DELAY`, etc.
- **🛡️ Logical Bypasses**: Targets complex tautologies like `' OR 1=1` and its many obfuscated variations.
- **🛡️ System Schema Access**: Prevents reconnaissance by blocking access to `information_schema`, `sqlite_master`, and system tables.

---

## 📜 XSS Shield (Modern Vector Defense)
Targeting DOM-based and event-driven JavaScript injection.
- **🛡️ Event Handlers**: Detects 50+ inline JavaScript handlers (e.g., `onload`, `onerror`, `onmouseover`).
- **🛡️ SVG Vectors**: Identifies XSS hidden in multimedia tags (`<svg onload=...>`, `<iframe src=javascript:...>`).
- **🛡️ DOM Intelligence**: Blocks high-risk functions like `eval()`, `document.cookie`, and `String.fromCharCode()`.

---

## 📦 DLP Shield (Data Loss Prevention)
- **🛡️ Inbound File Protection**: Blocks access to sensitive files like `.env`, `.git/`, SSH keys, and database dumps.
- **🛡️ Outbound Secret Redaction**: Intercepts response bodies and redacts AWS Keys, GitHub Tokens, and JWTs with `[REDACTED SECRET]`.

---

## 🍯 Deceptive Defense: Honeypot Shield
GuardianTUI implements **Active Deception** to trap and block automated scanners before they reach real application logic.
- **🛡️ 60+ Bait Paths**: Monitors access to ultra-sensitive paths like `/.env`, `/wp-config.php`, `/.aws/credentials`, and `/.git/config`.
- **🛡️ Multi-Layered Protection**: Detects configuration files, CMS admin panels, database dumps, and cloud infrastructure metadata probes.
- **🛡️ Zero-Tolerance Blocking**: In `IPS` and `Strict` modes, a single hit to a honeypot path results in an immediate, permanent IP block.
- **🛡️ Transparent Monitoring**: In `IDS` mode, honeypot hits are logged as critical alerts without blocking, allowing for deep behavioral observation.

---

## 📉 Behavioral Analysis: 404 Spike Detection
Beyond static signatures, GuardianTUI analyzes the *intent* of a client through its response history.
- **🛡️ Brute-Force Defense**: Automatically tracks `404 Not Found` responses per IP address.
- **🛡️ Intelligent Thresholding**: If an IP triggers an excessive number of 404s (e.g., 15+ within 60 seconds), it is identified as a directory brute-forcer (like `gobuster` or `dirb`) and auto-blocked.
- **🛡️ Memory Efficient**: Uses a 64-way sharded memory map to track thousands of concurrent IPs with near-zero latency.

---

## 🗺️ Offensive Framework Defense
Specifically targets the signatures of 30+ common security scanners and offensive frameworks.
- **🧪 sqlmap Shield**: Deep signature matching for `sqlmap`'s distinctive `UNION ALL SELECT NULL` and `CASE WHEN` probing logic.
- **🧪 Framework Detection**: Blocks signatures from `Cobalt Strike` (Beacons, reflective loaders), `Empire`, `Metasploit`, and `beEF`.
- **🔍 Scanner Defense**: Blocks `Nmap`, `Nikto`, `Acunetix`, `WPSCan`, `ZAP`, `Burp Suite`, and `Nuclei` through both User-Agent and custom header analysis.
