# 📡 Security Shields & Offensive Tooling Defense

GuardianTUI is equipped with a comprehensive suite of security shields designed to identify, block, and log common attack vectors. This document details the specific protections built into the engine.

---

## 🚨 Zero Tolerance: Anti-CSAM Shield
A specialized **Illicit Content Shield** that runs with absolute priority.

- **🧠 Multi-Layer Scoring**: Beyond simple keyword matching, it analyzes term combinations and context to identify CSAM-related content.
- **🔄 Advanced Obfuscation Bypass**: Detects attempts to hide illicit terms using leetspeak (e.g., `@` for `a`), Base64, or Hex encoding.
- **🤖 Integrated AI Safety**: Works in tandem with the AI Shield to prevent LLMs from generating, describing, or roleplaying illicit content.

---

## 💣 Metasploit & Exploit Shield
Protection against the most common exploitation frameworks and automated stagers.

- **🕵️ Meterpreter Detection**: Identifies Meterpreter transport patterns, including Payload UUIDs and session polling strings (`RECV`).
- **🧮 URI Checksum Heuristics**: Implements the Metasploit 8-bit checksum algorithm to block alphanumeric stagers (Windows, Java, Python, PHP).
- **🐚 PowerShell Stager Defense**: Blocks "One-Liner" stagers used by `web_delivery` and other MSF modules.
- **🛠️ Generic Exploit Mitigation**: Hardened signatures for **Log4j (JNDI)**, **Struts2 (OGNL)**, and Java deserialization.

---

## 🐚 Reverse Shell Shield
Real-time detection of TCP/UDP reverse shell one-liners across multiple languages.

- **🖥️ Scripting Support**: Bash, Python, Perl, PHP, Ruby, and Lua reverse shell patterns.
- **🛡️ Socket Redirection**: Identifies common `/dev/tcp` and `/dev/udp` redirections.
- **🔧 Netcat Mitigation**: Detects Netcat flags (`-e`, `-c`) and FIFO backpipe shell patterns.

---

## 📦 DLP Shield (Data Loss Prevention)
Prevents sensitive data from leaking in or out of your application.

- **🛡️ Inbound File Protection**: Blocks access to sensitive files like `.env`, `.git/`, SSH private keys (`id_rsa`), and `.sql` database dumps.
- **🛡️ Outbound Secret Redaction**: Intercepts response bodies and redacts AWS Keys, GitHub Tokens, Database Connection Strings, and JWTs with `[REDACTED SECRET]`.
- **🚨 Audit Injection**: Automatically injects an `X-DLP-Warning` header into responses when redaction occurs.

---

## 🗺️ Offensive Framework Defense
Specifically targets the signatures of common security scanners and frameworks.

- **🔍 Nmap Defense**: Blocks NSE (Nmap Scripting Engine) probes, including `http-sql-injection` and `http-enum`.
- **🧪 Nuclei & OAST Scanning**: Detects interaction domains like `interactsh.com`, `oastify.com`, and `oast.online`.
- **☕ Burp Suite Defense**: Blocks Burp Collaborator payloads and automated Intruder/Spider traffic.
- **🐝 BeEF Framework**: Identifies the Browser Exploitation Framework by targeting `hook.js` and common panel endpoints.
