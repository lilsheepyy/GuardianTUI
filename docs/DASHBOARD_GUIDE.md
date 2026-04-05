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
- **`ENTER`**: Press `Enter` on any log entry to open the **Deep Incident Inspector**.

---

## 🔍 Deep Incident Inspector
Press `Enter` while navigating the log table to open a full-screen report of a specific security event.

- **Event Identification**: ID, Timestamp, Source IP, and Path.
- **Security Analysis**: Detailed threat type, matched patterns, and risk level.
- **HTTP Headers**: View the full request headers as received by the proxy.
- **Raw Payload**: Inspect the original POST/PUT body or query strings.
- **De-obfuscated Payload**: GuardianTUI automatically normalizes the payload (URL decoding, HTML unescaping, Base64/Hex decoding) to reveal hidden attack patterns.

Press `Esc` or `Backspace` to return to the main dashboard.

---

## ⚙️ Interactive Config Editor
Press `c` to enter the **Configuration Editor**. This allows you to modify the engine's behavior in real-time without restarting.

- **System Mode**: Switch between `ips`, `ids`, and `strict` modes.
- **Detection Thresholds**: Adjust `Probing Threshold`, `Spam Threshold`, and `Probing Window`.
- **Security Shields**: Toggle `PoW Enabled` and `Honeypots` on or off.
- **Auto-Save**: Changes are applied immediately and saved to `config.yaml`.

**Navigation:**
- **`Tab / Down`**: Move to the next field.
- **`Shift+Tab / Up`**: Move to the previous field.
- **`Enter`**: Apply the value in the current field.
- **`Esc`**: Return to the main dashboard.

---

## ⌨️ Interactive Commands

GuardianTUI provides efficient keyboard shortcuts and a command-line interface for dashboard control:

### Terminal Mode (`/`)
Press `/` to open the terminal bar. The following commands are available:

- **`search <query>`**: Filter the log feed by **ID**, **Source IP**, or **Security Status**.
- **`themes set <name>`**: Change the dashboard's visual theme (e.g., `cyber`, `forest`, `dracula`, `monochrome`).
- **`modes set <name>`**: Change the operational mode (e.g., `ips`, `ids`, `strict`).
- **`clear`**: Resets all active filters and returns to the live feed.
- **`quit`**: Gracefully shuts down the proxy and exits.

### Direct Commands
- **`b`**: Select a row in the log table and press `b` to instantly add the Source IP to the blocklist.
- **`c`**: Open the Interactive Config Editor.
- **`Enter`**: Open the Deep Incident Inspector.

### Advanced Autocomplete
GuardianTUI features a smart **Tab-completion** system:
- **Command Completion**: Type a few letters (e.g., `the`) and press `Tab` to complete the command.
- **Argument Cycling**: Press `Tab` after `themes set ` or `modes set ` to cycle through all available options.
- **Top-level Cycling**: Press `Tab` on an empty prompt to cycle through all primary commands.

### Navigation
- **`ESC`**: Instantly clear the terminal input and return to live feed.
- **`Arrow Keys`**: Scroll through the history of captured attacks in the log table.
- **`Q` or `CTRL+C`**: Shutdown the proxy and exit.

---

## 🎨 Visual Themes

GuardianTUI supports multiple visual themes to suit your preference:

| Theme | Primary Colors | Vibe |
|-------|----------------|------|
| `cyber` (Default) | Cyan, Red, Emerald | High-tech security dashboard |
| `forest` | Green, Brown, Teal | Nature-inspired, easier on the eyes |
| `dracula` | Purple, Pink, Green | Classic dark mode developer palette |
| `monochrome` | White, Greys | Minimalist, high-contrast |

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
