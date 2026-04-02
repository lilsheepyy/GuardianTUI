# 🏛️ GuardianTUI Architecture & Internals

GuardianTUI is engineered for ultra-high performance and multi-layered defense in high-traffic environments.

---

## 🚀 High-Performance Sharding
- **ShardedIPMap**: Employs **64-way memory sharding** for IP tracking and bot detection to eliminate lock contention on high-concurrency servers.

---

## ⚡ Lock-Free Security Snapshots
- **`atomic.Pointer`**: Policies (Whitelists, Subnets) are managed via atomic snapshots, allowing zero-latency lookups during active traffic filtering without acquiring global read-locks.

---

## 🔄 Recursive Normalization & Anti-Obfuscation
Attackers often use obfuscation to bypass IPS signatures. GuardianTUI recursively decodes up to **4 layers** of encoding:
1.  **URL & Double URL Encoding**
2.  **HTML Entity Encoding**
3.  **Unicode Escape** (`\uXXXX`)
4.  **Hex Escape** (`\xHH` or `0x...`)
5.  **Base64 Strings**

---

## 🧠 Entropy Analysis (Anti-Encryption)
GuardianTUI calculates the **Shannon Entropy** of incoming payloads to identify data that is "too random."
- **Detection**: High entropy (above 5.8) is flagged as potentially encrypted shellcode, packed malware, or binary exploits.
- **Zero-Day Resilience**: This allows the engine to block unknown encrypted attacks that don't match existing signatures.

---

## 🌐 Network Hardening
- **Cloudflare Integration**: Prioritizes `CF-Connecting-IP` to identify real visitors behind the Cloudflare edge.
- **Unauthorized Proxy Shield**: Explicitly blocks requests containing the `X-Forwarded-For` header to prevent IP spoofing and unauthorized proxy-looping.

---

## 📝 Enterprise Logging Suite
- **Persistent JSON**: All events are saved in a structured JSON format for easy ingestion by ELK, Splunk, or custom SIEMs.
- **Auto-Rotation**: The system monitors the log file and automatically rotates it at **10MB** to protect disk space.
- **Default Storage**: Logs are securely stored in the dedicated `logs/` directory.
