# 📊 v2.0 Dashboard & TUI Guide

The GuardianTUI v2.0 Dashboard is a high-performance mission control center for monitoring your system in real-time. It is designed to be visually sophisticated yet highly responsive.

---

## 🛰️ Dashboard Layout

The v2.0 interface consists of four primary functional areas:

### 1. 📈 Traffic Heatmap & Activity Chart
A 60-second real-time graph that displays the ratio of **Safe** (Green) vs. **Alert** (Red) traffic.
- **`█` (Green)**: Allowed request.
- **`█` (Red)**: Blocked attack or malicious probe.
- **`·` (Dim)**: Idle time (no requests).

### 2. 🛡️ Threat Distribution
A ranked list of the most frequent attack types.
- **Bar Visualization**: Shows the percentage of each threat type relative to total blocks.
- **Top 5 Attack Vectors**: Instantly identify if your application is being targeted by a specific attack class (e.g., SQLi, Path Traversal).

### 3. ⚡ Real-Time Statistics Bar
High-level operational metrics updated every second.
- **UPTIME**: Current session duration.
- **TOTAL REQUESTS**: All traffic processed by the proxy.
- **IPS BLOCKS**: Total number of malicious requests blocked.
- **LIVE RPS**: Current Requests Per Second.

### 4. 📝 Security Log & Search
A live-scrolling feed of all security events.
- **`PASSIVE MONITORING`**: Legitimate traffic being logged.
- **`🛡️ DETECTED`**: Attack identified and logged.
- **`🚫 BLOCKED`**: High-risk attack blocked by the IPS.

---

## ⌨️ Interactive Commands

GuardianTUI provides efficient keyboard shortcuts for active incident investigation:

- **`/` (Search Mode)**: Filter the log feed by IP address, Attack Pattern, or Path.
- **`ESC`**: Clear the active filter and return to live feed.
- **`Arrow Keys`**: Scroll through the history of captured attacks.
- **`Q` or `CTRL+C`**: Shutdown the proxy and exit.

---

## 📱 Responsive Layout Support

The v2.0 dashboard is built to be resilient to window resizing.
- **Full Terminal**: Side-by-side view of the chart and distribution list.
- **Small/Narrow Terminal**: Vertical layout that stacks the visualization components for readability.
- **Safety**: Calculations are built to prevent negative heights or crashes regardless of terminal size.

---

## 🚨 Forensic Awareness

When a block occurs, a **Critical Incident Bar** appears at the bottom of the screen.
- **Context**: Displays the source IP, the targeted path, and the specific threat type detected.
- **Incident ID**: Every block is assigned a unique 8-character ID. The user sees this ID on their 403 Forbidden page, allowing you to correlate their report directly with the TUI log entry.
