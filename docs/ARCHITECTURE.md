# 🏛️ GuardianTUI Architecture & Internals

GuardianTUI is engineered for ultra-high performance and extreme reliability in high-traffic environments. This document explains the core architectural decisions that allow it to process thousands of requests per second while maintaining deep packet inspection.

---

## 🚀 High-Performance Sharding

To eliminate lock contention (a common bottleneck in Go applications with high concurrency), GuardianTUI employs **64-way memory sharding**.

- **ShardedIPMap**: Instead of a single `sync.Map` or a generic map with a global mutex, we partition the key space into 64 distinct "shards," each with its own `sync.RWMutex`.
- **Bot Probing Memory**: The same sharding logic is used to track the behavioral history of suspicious IPs, ensuring that thousands of simultaneous bot probes don't slow down legitimate traffic.

---

## ⚡ Lock-Free Security Snapshots

Security policies (Whitelists, Blocked Subnets, and Exact IP lists) are updated frequently by the background sync workers.

- **`atomic.Pointer` Usage**: When blocklists are updated (every 60s), the engine builds the new structures in a separate memory space. Once ready, it uses an atomic pointer swap to replace the active security snapshot.
- **Zero-Latency Lookups**: This design allows the request-handling hot-path to read the current security policy without ever acquiring a write lock, even during a heavy update cycle.

---

## 🔄 Recursive Normalization Engine

Attackers often use obfuscation to bypass IPS signatures. GuardianTUI's `utils.Normalize` function recursively decodes up to 3 layers of encoding:

1.  **URL Encoding** (e.g., `%27` -> `'`)
2.  **Double URL Encoding** (e.g., `%2527` -> `%27` -> `'`)
3.  **HTML Entity Encoding** (e.g., `&#x27;` -> `'`)
4.  **Base64/Hex Strings**: Identifies and decodes potential malicious payloads hidden in encoded strings.

---

## 🛡️ Transparent Proof of Work (PoW)

Against massive HTTP floods (DDoS), the engine employs a "Proof of Work" challenge.

- **Client-Side Cryptography**: When the PoW challenge is enabled, suspicious or high-frequency visitors are served an invisible JavaScript challenge.
- **Verification**: The client must solve a small cryptographic puzzle before their request is forwarded to the backend. This stops simple bots instantly while remaining invisible to real users.

---

## 🌐 Secure Reverse Proxy Logic

GuardianTUI acts as an L7 gateway. It manages:
- **TLS Termination**: Support for real Let's Encrypt certificates (via `autocert`) or self-signed certificates for local development.
- **Identification & Traceability**: Injects unique headers (`X-Protected-By`, `Via`) and cookies (`guardianTUI`) for downstream verification.
- **Payload Capture**: Buffers the request body for inspection only up to the `max_scan_size_bytes`, ensuring that large uploads don't consume excessive memory.
