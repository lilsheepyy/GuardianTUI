# ⚙️ Configuration & Customization Guide

GuardianTUI is highly configurable via `config.yaml` and `ai.json`. This guide provides a full reference for all available options.

---

## 📄 YAML Security Engine (`config.yaml`)

The main configuration file controls the intensity and reach of the security engine.

### Engine Configuration
- `mode`: The operational behavior of the proxy. Options:
    - `ips` (Default): Active mitigation. Blocks malicious requests.
    - `ids`: Passive monitoring. Logs detections but does not block traffic.
    - `strict`: Aggressive defense. Challenges all GET requests with PoW and enforces strict header policies.
- `max_scan_size_bytes`: Maximum size of the request body to scan. (Default: 1MB).
- `probing_window_seconds`: Time window (in seconds) used to track the behavioral history of an IP.
- `probing_threshold_unique`: The number of unique attack types (e.g., SQLi + XSS) an IP can attempt before being automatically blocked as a "Probing Bot". (Used also for 404 Spike Detection).
- `spam_threshold_total`: The total number of blocked requests an IP can make before its IP is blacklisted.
- `pow_enabled`: Enable or disable the transparent Anti-DDoS PoW challenge. (Default: `false`).
- `pow_difficulty`: Cryptographic complexity of the PoW puzzle. (Default: `4`).

### Deception & Honeypots
- `honeypot_paths`: A custom list of sensitive-looking paths (e.g., `["/.env", "/wp-admin"]`).
    - **Defaults**: If empty, GuardianTUI uses a pre-configured list of 60+ bait paths.
    - **TUI Command**: Honeypots can be toggled at runtime using `/honeypots set <on/off>`.

### AI & Prompt Protection
- `endpoints`: A list of URL prefixes that require deep heuristic scoring (e.g., `["/v1/chat", "/api"]`).
- `score_threshold`: The cumulative "Threat Score" required to block a request on AI-specific endpoints. (Default: `5`).
- `protect_pii`: Enable automated blocking of SSNs, Credit Card numbers, and other PII in prompt submissions.
- `blocked_keywords`: A list of high-risk terms that trigger an instant block when found in a request body.

---

## 🧠 Custom AI Heuristics (`ai.json`)

Define your own weighted patterns for LLM prompt protection.

```json
[
  {
    "pattern": "(?i)reveal your secret key",
    "weight": 5,
    "description": "Secret Key Leakage Attempt"
  },
  {
    "pattern": "(?i)ignore all previous instructions",
    "weight": 3,
    "description": "Jailbreak / Instruction Override"
  }
]
```

If the sum of weights for all matched patterns in a single request reaches the `score_threshold` set in `config.yaml`, the request is blocked.

---

## 📡 IP Blocklist Management

GuardianTUI automatically handles massive blocklists and refreshes them every minute.

### 🚫 Global Threat Feeds
We pre-configure feeds from **FireHOL**, **Spamhaus**, **AbuseIPDB**, and **SSL Proxies**.

### 🛠️ Local Custom Lists
- `blocklist_path`: Path to a local text file containing IPs or CIDR subnets (one per line).
- `remote_blocklists`: A list of URLs pointing to plain-text IP lists.

### 🔍 Cache & Sanitization
GuardianTUI maintains a persistent local cache in the `proxylistblock/` folder.
- **Sanitization**: Comments (`;` or `#`) and metadata are automatically stripped to ensure high-speed processing.
- **Audit**: You can inspect the sanitized files in the `proxylistblock/` directory at any time.

---

## 🛡️ Whitelisting
- `whitelist`: A list of IPs or CIDR subnets that should bypass all security checks. **GuardianTUI always prioritizes the whitelist over any blocklist.**
