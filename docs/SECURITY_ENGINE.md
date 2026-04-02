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

## 🗺️ Offensive Framework Defense
Specifically targets the signatures of common security scanners and frameworks.
- **🔍 Nmap Defense**: Blocks NSE (Nmap Scripting Engine) probes.
- **🧪 Nuclei & OAST Scanning**: Detects interaction domains like `interactsh.com`.
- **☕ Burp Suite Defense**: Blocks Burp Collaborator payloads and automated intruder traffic.
