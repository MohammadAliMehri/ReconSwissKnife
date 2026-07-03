<p align="center">
  <img src="https://img.shields.io/badge/Platform-Burp_Suite-orange?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/Language-Jython_2.7-blue?style=for-the-badge" alt="Language">
  <img src="https://img.shields.io/badge/Version-3.0-brightgreen?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License">
</p>

# 🔪 Recon Swiss Knife Pro v3

### Semi-Active Security Recon & Method Fuzzer for Burp Suite

> A production-grade Burp Suite extension for passive reconnaissance, semi-active probing, and active cross-method fuzzing — all in one sleek, dark-mode dashboard.

---

## ✨ Key Features

### 🔍 Passive Reconnaissance Engine
- **Endpoint & Parameter Extraction** — Automatically collects all URLs, query parameters, POST body parameters, and JSON keys from proxied traffic.
- **JavaScript File Discovery** — Detects `.js` files from URL paths and HTML `<script src="">` tags.
- **HTTP Method Detection** — Flags risky HTTP methods (`PUT`, `DELETE`, `TRACE`, `PATCH`, `OPTIONS`, `DEBUG`, `CONNECT`).
- **Security Header Auditing** — Checks for missing or misconfigured `X-Frame-Options`, `Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, and `X-XSS-Protection`.
- **Cookie Security Analysis** — Detects cookies missing `Secure` or `HttpOnly` flags.

### 🇮🇷 Iranian Target Focus
- **National ID Validation** — Detects 10-digit Iranian National ID numbers with full checksum verification.
- **Mobile Number Detection** — Identifies Iranian mobile numbers in `+98`, `0098`, and `09xx` formats.

### 🔐 Advanced Secret Detection Engine
| Secret Type | Regex Pattern |
|---|---|
| OpenAI / Anthropic API Keys | `sk-[A-Za-z0-9]{32,}` |
| Google Cloud / YouTube API Keys | `AIzaSy[A-Za-z0-9_\-]{33}` |
| GitHub Personal Access Tokens | `ghp_[A-Za-z0-9]{36}` |
| Firebase Database URLs | `https?://[a-z0-9\-]+\.firebaseio\.com` |
| AWS Access Keys | `(AKIA\|ASIA)[0-9A-Z]{16}` |
| AWS Secret Keys | Context-aware pattern matching |
| JWT Tokens | `ey[...].{...}.{...}` three-part structure |
| Bearer Tokens | `bearer [token]` header values |
| Generic API Keys / Secrets | `api_key`, `access_token`, `secret_key` patterns |
| Email Addresses | Standard RFC-like email patterns |

### 🌐 Semi-Active Modules
- **Auto JS Deep-Fetch** — Proactively downloads in-scope JavaScript files and scans them for hidden API endpoints, S3 buckets, cloud storage URLs, fetch/AJAX targets, and relative API paths.
- **Auto Method Probe (OPTIONS/HEAD)** — Sends lightweight `OPTIONS` requests (with `HEAD` fallback) to discovered endpoints to enumerate allowed HTTP methods via `Allow` headers.

### ⚡ Active Cross-Method Fuzzer
- **Right-Click Fuzzing** — Select any endpoint row, right-click → *"Test Risky Methods (Fuzz Endpoint)"*.
- **Method Coverage** — Sends `PUT`, `DELETE`, `PATCH`, `DEBUG`, and `TRACE` requests.
- **Bypass Detection** — Flags responses with status codes `200`, `201`, or `204` as **"VULNERABLE (Bypass Confirmed)"**.
- **Full Logging** — All fuzz results (including blocked attempts) are logged with the complete HTTP request/response for review.

### 🖥️ Professional UI/UX
- **Dark-Mode / Light-Mode Auto-Detection** — Adapts to Burp's current theme automatically.
- **Live Dashboard** — 8 metric cards with real-time counters for endpoints, JS files, findings, leaks, processed items, and active tasks.
- **Tab Count Badges** — Each tab title shows a live count of its findings (e.g., `"Leaks (42)"`).
- **No Wasted Space** — The bottom split-pane has been removed; tables occupy the full viewport.
- **Interactive Search & Scope Filtering** — Filter all tables in real-time with regex-aware search.

### 🔎 Native Pop-up Viewer (Double-Click)
- **Full Request/Response** — Opens a resizable, non-modal `JDialog` with Burp's native `IMessageEditor`, showing **Raw**, **Headers**, and **Hex** tabs.
- **Leak Auto-Highlighting** — When double-clicking a leak row, the popup includes an `ITextEditor` panel with the leaked secret value automatically highlighted and scrolled to.
- **JS Beautifier** — When inspecting a `.js` file, the response body is automatically beautified with proper indentation before display.

---

## 📦 Installation

### Prerequisites
- **Burp Suite** Professional or Community Edition (2020.x or later recommended)
- **Jython Standalone JAR** (2.7.x) — [Download from jython.org](https://www.jython.org/download)

### Step 1: Configure Jython in Burp Suite

1. Open Burp Suite.
2. Navigate to **Extensions → Extension Settings** (or **Extender → Options** in older versions).
3. Under **Python Environment**, click **Select file...** and browse to your downloaded `jython-standalone-2.7.x.jar`.
4. Burp will confirm the Jython environment is configured.

### Step 2: Load the Extension

1. Go to **Extensions → Installed** (or **Extender → Extensions**).
2. Click **Add**.
3. Set **Extension type** to **Python**.
4. Click **Select file...** and browse to `ReconSwissKnife_v3.py`.
5. Click **Next** — the extension will load and a new tab **"Recon Swiss Knife"** will appear.

### Step 3: Verify

Check the **Output** tab in the extension details — you should see:
```
Recon Swiss Knife Pro v3 loaded successfully.
```

---

## 🚀 Usage

### Basic Workflow

1. **Set Scope** *(optional)* — Enter comma-separated domain keywords in the **Scope Filter** field (e.g., `example.com, api.target`). Leave empty to process all traffic.

2. **Enable Passive Recon** — Click the **"Passive Recon: OFF"** button to toggle it **ON** (turns green). This will:
   - Scan existing proxy history.
   - Begin monitoring live traffic in real-time.

3. **Browse Your Target** — Navigate the target application normally. The extension passively extracts findings.

4. **Review Findings** — Check each tab for results:
   - **Endpoints & Params** — Discovered URLs with methods and parameters.
   - **HTTP Methods & Headers** — Risky methods and missing security headers.
   - **JS Files** — Discovered JavaScript files.
   - **Leaks** — Exposed secrets, tokens, PII.
   - **JS Deep Findings** — Hidden endpoints found inside JS files.
   - **Method Probe Results** — Allowed methods per endpoint.
   - **Method Fuzz Results** — Active fuzzing results.

### Inspecting Findings (Double-Click)

Double-click any row in any table to open the **Request/Response Popup**:
- View the full HTTP request and response with Burp's native message editor.
- For **Leak** rows: the leaked value is automatically highlighted in the response body.
- For **JS** rows: the response body is automatically beautified with proper indentation.

### Active Fuzzing (Right-Click)

1. Right-click any row in any table.
2. Select **"Test Risky Methods (Fuzz Endpoint)"**.
3. The extension will send `PUT`, `DELETE`, `PATCH`, `DEBUG`, and `TRACE` requests to the endpoint.
4. Results appear in the **"Method Fuzz Results"** tab.
5. Rows marked **"VULNERABLE (Bypass Confirmed)"** indicate the server accepted a risky method with a success status code.

### Semi-Active Modules

- **Auto Deep-Fetch JS** *(checkbox)* — When enabled, the extension automatically downloads newly-discovered `.js` files and scans them for hidden endpoints and cloud resources.
- **Auto Method Probe** *(checkbox)* — When enabled, sends `OPTIONS`/`HEAD` requests to new endpoints to discover allowed HTTP methods.

### Additional Features

- **Rescan Proxy History** — Re-analyze all existing proxy traffic.
- **Clear Data** — Reset all findings and counters.
- **Search / Filter** — Real-time regex search across all tables.
- **Right-Click → Copy** — Copy URLs, parameters, or match values to clipboard.
- **Right-Click → "Send to Recon Swiss Knife"** — Available in Burp's own tools (Proxy, Repeater, etc.) to manually feed items into the extension.

---

## 📸 Screenshots

> *Screenshots will be added after initial deployment.*

| View | Description |
|---|---|
| Dashboard | Main interface with metric cards and tabbed data tables |
| Leak Popup | Double-click popup with auto-highlighted secret value |
| JS Viewer | Beautified JavaScript response in popup |
| Fuzz Results | Method fuzz results showing bypass detections |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────┐
│              BurpExtender (Main)             │
│  IHttpListener + ITab + IContextMenuFactory  │
│  + IExtensionStateListener                   │
├─────────────────┬───────────────────────────┤
│  ReconAnalyzer  │     ActiveEngine          │
│  (Passive)      │  (Semi-Active / Active)   │
│  - Endpoints    │  - JS Deep-Fetch          │
│  - Parameters   │  - Method Probe           │
│  - JS Files     │  - Cross-Method Fuzz      │
│  - Leaks/PII    │  - ExecutorService Pool   │
│  - Headers      │                           │
├─────────────────┴───────────────────────────┤
│              DataStore (Thread-Safe)         │
│  All findings retain IHttpRequestResponse   │
├─────────────────────────────────────────────┤
│              ReconUI (Swing EDT)             │
│  - Dashboard + Metric Cards                 │
│  - 7 Tabbed Data Tables                     │
│  - RequestResponsePopup (JDialog)           │
│  - Leak Highlighting (ITextEditor)          │
│  - JS Beautifier (Pure Python)              │
└─────────────────────────────────────────────┘
```

---

## ⚠️ Disclaimer

> **This tool is intended for authorized security testing and educational purposes only.**
>
> Use this extension **only** against systems you have explicit written permission to test. Unauthorized access to computer systems is illegal in most jurisdictions. The authors assume **no liability** for misuse of this tool.
>
> By using this software, you agree to comply with all applicable local, state, national, and international laws and regulations.
>
> **The semi-active and active modules (JS Deep-Fetch, Method Probe, Cross-Method Fuzz) send real HTTP requests to target servers.** Ensure you have proper authorization before enabling these features.

---

## 📄 License

This project is provided under the [MIT License](LICENSE).

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome. Please open an issue or submit a pull request.

---

<p align="center">
  <b>Made with ☕ for the security community</b>
  <br>
  <sub>Recon Swiss Knife Pro v3 — Because every endpoint deserves a second look.</sub>
</p>
