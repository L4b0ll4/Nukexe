
<p align="center">
  <img src="nukexe.png" alt="Nukexe Logo" width="128" height="128">
</p>

<h1 align="center">Nukexe</h1>

<p align="center">
  <strong>Dynamic REST API Gateway & Web Management UI for Windows Executables</strong>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License"></a>
  <img src="https://img.shields.io/badge/Platform-Windows-0078D6.svg?logo=windows" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python" alt="Python">
</p>

---

## ⚡ Overview

**Nukexe** turns any local Windows executable, batch file (`.bat`, `.cmd`), or PowerShell script (`.ps1`) into secure, authenticated REST API endpoints on the fly. 

It runs as a silent, background daemon with a System Tray icon and provides a rich web dashboard (`/admin/ui`) to configure routes, control tokens, inspect logs, monitor jobs, and manage system security.

---

## 🚀 Key Features

- **Dynamic REST Endpoints**: Map `/{TOOL}/{FUNCTION}` directly to command-line processes.
- **Dynamic Argument Templating**: Inject parameters from incoming JSON directly into CLI args using `{$param}` and `{$nested.param}` syntax.
- **Sync & Async Execution**:
  - **Synchronous**: Block and return stdout, stderr, exit code, and execution time directly.
  - **Asynchronous**: Return a `job_id` (HTTP 202) and execute via a managed worker pool with optional webhook callbacks.
- **Zero-Dependency Single Binary**: Packs into a single standalone `.exe` using PyInstaller.
- **Built-in Web Dashboard**: Full SPA dashboard with Dark/Light modes, i18n (Italian/English), and live updates.
- **Enterprise-Grade Security**:
  - Bearer Token authentication (Admin & Standard roles).
  - Built-in **Fail2Ban** (automatic IP bans on repeated anomalies/floods).
  - Sliding-window **Rate Limiting** (Global and Per-Route).
  - Anti-replay **Deduplication Cache** (prevents identical concurrent runs).
  - Granular IP Whitelisting and Blacklisting.
  - Reverse proxy support (`X-Forwarded-For`).
- **Observability & Alerts**:
  - Full Audit Trail stored in SQLite WAL.
  - Granular Admin Activity Logging.
  - Outbound **Webhooks** with HMAC-SHA256 signature support.
  - Outbound **SMTP Email** notifications with anti-flood deduplication.

---

## 🛠️ Installation & Building (Windows)

### Prerequisites
- Windows 10 / 11 / Server 2016+
- Python 3.10 or higher
- Git

### 1. Clone & Set Up Environment
```cmd
git clone https://github.com/L4b0ll4/Nukexe.git
cd nukexe

python -m venv venv
call venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Build Standalone `.exe`
Run the included build script:
```cmd
build.bat
```

Or execute PyInstaller directly:
```cmd
pyinstaller --noconsole --onefile --name Nukexe ^
    --add-data "dashboard.html;." ^
    --add-data "nukexe.png;." ^
    --add-data "nukexe.ico;." ^
    --collect-submodules uvicorn ^
    --icon nukexe.ico ^
    --version-file=version.txt ^
    Nukexe.py
```
The compiled binary will be placed inside `dist\Nukexe.exe`.

---

## 🚦 First Launch

1. Double-click `Nukexe.exe`.
2. A startup popup will display your web dashboard URL and generate the **initial Admin Bearer Token**.
3. Copy the token and access the web dashboard:
   ```text
   http://localhost:8000/admin/ui
   ```
4. Paste your token in the top-right field to authenticate.

> **Note**: Database (`Nukexe.db`) and logs (`Nukexe.log`) will be created in the same folder where `Nukexe.exe` resides. Ensure the binary is placed in a writable directory (avoid `C:\Program Files\` directly unless running elevated).

---

## 📖 API Usage Example

### 1. Configure Route in Dashboard
- **Path**: `NETWORK/PING`
- **Executable**: `C:\Windows\System32\ping.exe`
- **Template**: `-n 2 {$target}`
- **Auth**: Enabled

### 2. Call the Endpoint
```bash
curl -X POST "http://localhost:8000/NETWORK/PING" \
  -H "Authorization: Bearer exe_your_token_here" \
  -H "Content-Type: application/json" \
  -d '{"params": {"target": "1.1.1.1"}}'
```

### 3. Response
```json
{
  "exit_code": 0,
  "stdout": "\nPinging 1.1.1.1 with 32 bytes of data:\nReply from 1.1.1.1: bytes=32 time=12ms TTL=57\n...",
  "stderr": "",
  "duration_ms": 1024.15,
  "command": "C:\\Windows\\System32\\ping.exe -n 2 1.1.1.1"
}
```

---

## 🔒 Security Architecture

| Feature | Description |
| :--- | :--- |
| **Token ACLs** | Individual routes can restrict access to specific token IDs. |
| **Safe vs Dangerous Mode** | In `safe` mode, only pre-configured binaries are executed. `dangerous` mode allows dynamic executable injection (`_exe` in body) and strictly forces authentication. |
| **Fail2Ban Engine** | Automatically bans IPs exceeding $N$ failures within a rolling window. |
| **Anti-Replay / Dedup** | Caches matching command hashes for $N$ seconds to mitigate accidental duplicate execution. |
| **Safe Callbacks** | Async callbacks validate destinations and drop RFC1918 private IPs unless explicitly enabled. |

---

## 📄 License

This project is licensed under the [MIT License](LICENSE) - see the LICENSE file for details.

Developed by **Massimo Plachesi**.
