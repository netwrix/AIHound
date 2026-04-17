# AIHound

**AI Credential & Secrets Scanner**

<p align="center">
  <img src="aihound.png" alt="AIHound" width="500">
</p>

AIHound scans your system for credentials, secrets, and tokens stored by popular AI desktop applications and coding assistants. It checks config files, credential stores, MCP server configurations, and environment variables — then reports what it finds with risk-rated output.

This is a security research tool. Credentials are **redacted by default** so output is safe to share in reports and screenshots.

## What It Finds

AIHound doesn't just look for API keys. It scans for:

- **OAuth access & refresh tokens** (Claude, Copilot, ChatGPT)
- **API keys** (OpenAI, Anthropic, Google, AWS, Hugging Face, Replicate, Together, Groq, etc.)
- **MCP server secrets** — inline tokens, auth headers, and credentials embedded in MCP configurations
- **AWS credentials** — access keys, secret keys, session tokens, SSO cache
- **Google Cloud ADC** — application default credentials, service account keys
- **Docker registry credentials** — base64-encoded auth blobs in `~/.docker/config.json`
- **Git credential stores** — plaintext `~/.git-credentials`, embedded tokens in gitconfig
- **Jupyter server configs** — unauthenticated tokens, empty passwords, kernel env secrets
- **VS Code extension secrets** — tokens stored in extension globalStorage beyond Copilot/Cline
- **Browser AI sessions** — Firefox localStorage for claude.ai, chatgpt.com, gemini, etc.
- **PowerShell history** — API keys and tokens pasted into PSReadLine history or transcripts
- **Local AI server exposure** — detects Ollama, LM Studio, Jupyter, Gradio, vLLM, LocalAI, Open WebUI, ComfyUI listening on all interfaces without authentication
- **Environment variables** — 35+ known AI-related env vars
- **Plaintext config files** — `.env` files, JSON configs with hardcoded secrets

Every finding includes **actionable remediation guidance** and **file staleness** (when the credential was last modified) in verbose mode.

## Supported Tools

**25 scanners** covering AI assistants, CLI tools, developer tools, and infrastructure:

### AI Assistants & Desktop Apps
| Tool | What's Scanned |
|---|---|
| **Claude Code CLI** | `~/.claude/.credentials.json`, `~/.claude.json` MCP config, Keychain |
| **Claude Desktop** | `claude_desktop_config.json`, MCP server env vars & headers |
| **ChatGPT Desktop** | App data directories (macOS & Windows) |

### AI Coding Assistants & IDEs
| Tool | What's Scanned |
|---|---|
| **GitHub Copilot** | Keychain/Credential Manager, `~/.copilot/config.json`, VS Code storage, `gh` CLI hosts.yml |
| **Cursor IDE** | `~/.cursor/mcp.json`, app config directories |
| **Continue.dev** | `~/.continue/config.json` (plaintext API keys) |
| **Cline** | `cline_mcp_settings.json` (plaintext MCP creds) |
| **Windsurf** | `~/.codeium/windsurf/` config and MCP settings |
| **Aider** | `~/.aider.conf.yml` provider API keys |
| **VS Code Extensions** | Extension globalStorage tokens (AWS Toolkit, GitLens, Thunder Client, etc.) |

### AI CLIs & Platform Tools
| Tool | What's Scanned |
|---|---|
| **OpenAI / Codex CLI** | `~/.openai/api_key`, `auth.json`, `~/.codex/` configs |
| **Hugging Face CLI** | `~/.cache/huggingface/token`, `~/.huggingface/token` |
| **Gemini CLI / GCloud** | `.env` files, application default credentials |
| **Amazon Q / AWS** | `~/.aws/credentials`, SSO cache tokens |
| **Replicate / Together / Groq** | `~/.replicate/auth`, `~/.together/`, `~/.groq/` configs |
| **OpenClaw** | `~/.openclaw/` auth profiles, channel creds, gateway tokens, `.env`, legacy OAuth |

### Local AI Servers & Network Exposure
| Tool | What's Scanned |
|---|---|
| **Ollama** | `~/.ollama/`, env vars, systemd service, network exposure (port 11434) |
| **LM Studio** | App config dirs, HF tokens, `.env` files, network exposure (port 1234) |
| **Jupyter** | Notebook/server configs (`.py` + `.json`), kernel env secrets, empty-token detection |
| **AI Network Exposure** | Detects Jupyter (8888), Gradio (7860), vLLM (8000), LocalAI (8080), Open WebUI (3000), ComfyUI (8188) bound to `0.0.0.0` |

### Developer & Infrastructure
| Tool | What's Scanned |
|---|---|
| **Docker** | `~/.docker/config.json` — base64 auth blobs, identity tokens, credential helpers |
| **Git Credentials** | `~/.git-credentials`, `~/.gitconfig` embedded tokens |
| **PowerShell Logs** | PSReadLine `ConsoleHost_history.txt`, transcripts — detects tokens typed or pasted at the command line |
| **Browser Sessions** | Firefox localStorage for AI domains (claude.ai, chatgpt.com, gemini, perplexity, etc.); Chromium stub |
| **Environment Variables** | 35+ AI-related env vars (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, etc.) |

## Platform Support

| Platform | Status |
|---|---|
| **Linux** | Full support |
| **macOS** | Full support (includes Keychain queries) |
| **Windows** | Full support (includes Credential Manager) |
| **WSL** | Full support — scans **both** Linux paths and Windows paths via `/mnt/c/` |

---

# Installation
### **Precompiled .exe version can be found [Here](https://github.com/netwrix/AIHound/tree/main/Other%20Versions/pyinstaller/dist)**

AIHound can be run four ways: from Python source, using the Go runtime. as a compiled Go binary, or as a standalone Windows executable (via PyInstaller).

---

## 1. Python Source (Original)

### Prerequisites
- Python 3.10+
- pip

### Install
```bash
# Clone the repo
git clone https://github.com/netwrix/aihound.git
cd aihound

# Run directly (zero dependencies for core scanning)
python3 -m aihound

# Optional: install rich for colored table output
pip install -r requirements.txt
pip install rich
```

### Run
```bash
python -m aihound
python -m aihound --verbose
python -m aihound --json
python -m aihound --html-file report.html
python -m aihound --show-secrets
python -m aihound --tools claude-code cursor ollama
python -m aihound --list-tools
```

---

## 2. Go Binary

The Go version is a complete rewrite with full feature parity. It produces a single static binary with zero runtime dependencies.

### Prerequisites
- Go 1.22+ ([download](https://go.dev/dl/))

### Build for Current Platform

```bash
cd Go
go mod tidy       # first time only — downloads dependencies and generates go.sum
go build -o aihound ./cmd/aihound
```

On Windows:
```cmd
cd Go
go mod tidy
go build -o aihound.exe ./cmd/aihound
```

### Cross-Compilation

Go can build for any OS/architecture from any host machine. No additional toolchains needed:

```bash
cd Go

# Windows (amd64)
GOOS=windows GOARCH=amd64 go build -o aihound.exe ./cmd/aihound

# Windows (ARM64)
GOOS=windows GOARCH=arm64 go build -o aihound-arm64.exe ./cmd/aihound

# macOS (Intel)
GOOS=darwin GOARCH=amd64 go build -o aihound-macos ./cmd/aihound

# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o aihound-macos-arm64 ./cmd/aihound

# Linux (amd64)
GOOS=linux GOARCH=amd64 go build -o aihound-linux ./cmd/aihound

# Linux (ARM64, e.g. Raspberry Pi)
GOOS=linux GOARCH=arm64 go build -o aihound-linux-arm64 ./cmd/aihound
```

All builds use pure Go (no CGO required), so `CGO_ENABLED=0` works for all targets. The SQLite dependency (`modernc.org/sqlite`) is a pure Go implementation, so cross-compilation works without a C compiler.

On Windows PowerShell, set environment variables like this:
```powershell
$env:GOOS="linux"; $env:GOARCH="amd64"; go build -o aihound-linux ./cmd/aihound
```

### Run

Linux / macOS:
```bash
./aihound                    # full scan with table output
./aihound --verbose          # debug output with permissions and file owners
./aihound --json             # JSON output to stdout
./aihound --json-file report.json   # JSON report to file
./aihound --html-file report.html   # self-contained HTML report
./aihound --show-secrets     # show actual credential values (requires "YES" confirmation)
./aihound --tools claude-code --tools cursor --tools ollama   # scan specific tools only
./aihound --list-tools       # list all available scanners
./aihound --no-color         # disable ANSI colors (useful for piping)
```

Windows:
```cmd
aihound.exe
aihound.exe --verbose
aihound.exe --json-file report.json
aihound.exe --html-file report.html
```

### WSL Note

When running the Go binary on WSL, it automatically detects the WSL environment and scans **both** Linux credential paths (`~/.claude/`, `~/.config/`, etc.) and Windows credential paths (`/mnt/c/Users/<you>/AppData/`, `/mnt/c/Users/<you>/.claude/`, etc.). This gives a complete view of all credentials accessible from the WSL environment.

---

## 3. PyInstaller Windows Executable

Packages the Python version as a standalone `.exe` — no Python installation needed on the target machine.

### Prerequisites
- Python 3.10+ (for building only)
- pip
- **Must be built on Windows** (PyInstaller cannot cross-compile)

### Build

From Windows Command Prompt or PowerShell:
```cmd
cd pyinstaller
pip install -r requirements.txt
python build.py
```

From WSL (if Windows Python is accessible):
```bash
cd pyinstaller
python.exe -m pip install pyinstaller rich
python.exe build.py
```

Output: `pyinstaller/dist/aihound.exe` (~14 MB)

### Run

```cmd
aihound.exe                              # full scan with table output
aihound.exe --verbose                    # debug output
aihound.exe --json                       # JSON output to stdout
aihound.exe --json-file report.json      # JSON report to file
aihound.exe --html-file report.html      # self-contained HTML report
aihound.exe --show-secrets               # show actual credential values
aihound.exe --tools claude-code cursor   # scan specific tools only
aihound.exe --list-tools                 # list all available scanners
aihound.exe --no-color                   # disable ANSI colors
```

### Distributing

The `.exe` is fully self-contained. Copy it to any Windows machine and run it — no Python or other dependencies needed. On first run, Windows Defender or other AV software may briefly scan the executable, causing a short startup delay (~1-5 seconds).

### Rebuilding After Changes

If you modify the Python source, rebuild the `.exe`:
```cmd
cd pyinstaller
python build.py
```

PyInstaller caches intermediate build artifacts in `pyinstaller/build/`. To do a clean rebuild:
```cmd
cd pyinstaller
python build.py --clean
```

## CLI Reference

All flags are the same across all three versions:

| Flag | Description |
|------|-------------|
| `--version` | Show version and exit |
| `--show-secrets` | Display actual credential values (requires interactive "YES" confirmation) |
| `--json` | Output JSON to stdout |
| `--json-file PATH` | Write JSON report to file (creates parent dirs, expands `~`) |
| `--html-file PATH` | Write HTML report to file (creates parent dirs, expands `~`) |
| `--banner PATH` | Custom banner image for HTML report |
| `--tools TOOL ...` | Only scan specified tools (by slug) |
| `--list-tools` | List all available scanners |
| `-v`, `--verbose` | Show debug output, permissions, and stack traces |
| `--no-color` | Disable ANSI color codes |
| `--watch` | Run continuously, alert on changes (Ctrl+C to stop) |
| `--interval SECONDS` | Watch polling interval (default: 30) |
| `--watch-log PATH` | Append watch events as NDJSON to file |
| `--notify` | Fire OS-native desktop notifications for watch events |
| `--notify-min-risk LEVEL` | Minimum risk to notify on (default: `high`) |
| `--min-risk LEVEL` | Minimum risk to emit as watch events (default: `info`) |
| `--debounce SECONDS` | Suppress duplicate events within window (default: 10) |
| `--mcp` | Run as MCP stdio server (requires `pip install aihound[mcp]`) |

---

## Watch / Monitor Mode (v3.0.0)

AIHound can run continuously and alert you the moment a new credential appears, a file's permissions change, or a local AI server starts listening on `0.0.0.0`. Perfect for individual developers — leave it running in a terminal tab or background tmux pane.

```bash
aihound --watch                                          # 30s polling, terminal alerts
aihound --watch --interval 15                            # faster polling
aihound --watch --notify                                 # OS-native desktop toasts for HIGH+ events
aihound --watch --notify --notify-min-risk CRITICAL      # only toast on CRITICAL
aihound --watch --min-risk HIGH                          # suppress all INFO/MEDIUM events entirely
aihound --watch --watch-log ~/.aihound/watch.log         # append NDJSON log to file
aihound --watch --json                                   # NDJSON stream to stdout (pipe into anything)
aihound --watch --tools claude-code powershell           # scope to specific scanners
```

### Event types

| Event | When it fires |
|-------|---------------|
| `BASELINE` | Credential existed at startup (first scan only) |
| `NEW` | Credential appeared since last scan |
| `REMOVED` | Credential gone since last scan |
| `PERMISSION_CHANGED` | File permissions changed (e.g., `0600` → `0644`) |
| `CONTENT_CHANGED` | File mtime or value preview changed |
| `RISK_ESCALATED` | Risk level went up (e.g., `MEDIUM` → `CRITICAL`) |
| `NETWORK_EXPOSED` | Local AI server started listening on `0.0.0.0` |

### Example output

```
+-+-+-+-+-+-+-+
|N|e|t|w|r|i|x|
+-+-+-+-+-+-+-+
...AIHound banner...
Watch mode: interval=30s, scanners=25, min-risk=info. Press Ctrl+C to stop.

[10:42:17] BASELINE  CRITICAL  Claude Code CLI      oauth_access_token       ~/.claude/.credentials.json
[10:42:17] BASELINE  HIGH      Docker               credsStore               ~/.docker/config.json
[10:45:03] NEW       CRITICAL  Aider                openai-api-key           ~/.aider.conf.yml
[10:47:11] PERM+     CRITICAL  Claude Code CLI      oauth_access_token       ~/.claude/.credentials.json
            └─ Permissions: 0600 → 0644
[10:51:22] NETWORK   CRITICAL  Ollama               network_exposure        0.0.0.0:11434

Watch stopped. 5 event(s) emitted.
```

### NDJSON log format

With `--watch-log <path>` or `--json`, events are emitted as one JSON object per line:

```json
{"event_type":"new","timestamp":"2026-04-16T14:45:03Z","finding":{"tool_name":"Aider","credential_type":"openai-api-key","storage_type":"plaintext_yaml","location":"~/.aider.conf.yml","risk_level":"critical","value_preview":"sk-proj-...xyz","remediation":"Use environment variables..."}}
{"event_type":"permission_changed","timestamp":"2026-04-16T14:47:11Z","finding":{...},"previous_finding":{"file_permissions":"0600",...}}
```

Pipe into `jq`, `grep`, a log shipper, a SIEM, whatever.

---


### Available Scanners (25 total)

| Slug | Tool |
|------|------|
| `aider` | Aider |
| `amazon-q` | Amazon Q / AWS |
| `browser-sessions` | Browser Sessions (Firefox + Chromium stub) |
| `chatgpt` | ChatGPT Desktop |
| `claude-code` | Claude Code CLI |
| `claude-desktop` | Claude Desktop |
| `cline` | Cline (VS Code) |
| `continue-dev` | Continue.dev |
| `cursor` | Cursor IDE |
| `docker` | Docker |
| `envvars` | Environment Variables |
| `gemini` | Gemini CLI / GCloud |
| `git-credentials` | Git Credentials |
| `github-copilot` | GitHub Copilot |
| `huggingface` | Hugging Face CLI |
| `jupyter` | Jupyter |
| `lm-studio` | LM Studio |
| `ml-platforms` | ML Platforms (Replicate / Together / Groq) |
| `network-exposure` | AI Network Exposure |
| `ollama` | Ollama |
| `openai-cli` | OpenAI / Codex CLI |
| `openclaw` | OpenClaw |
| `powershell` | PowerShell Logs |
| `vscode-extensions` | VS Code Extensions |
| `windsurf` | Windsurf |

---

## Comparison

| | Go Binary | PyInstaller .exe | Python Source |
|---|---|---|---|
| **Size** | ~12 MB | ~14 MB | N/A (needs Python) |
| **Startup** | Instant | ~1-5s (extract, varies with AV) | Instant |
| **Runtime Dependencies** | None | None | Python 3.10+ |
| **Cross-Compile** | Yes (any OS to any OS) | No (must build on Windows) | N/A |
| **Supported Platforms** | Windows, macOS, Linux, WSL | Windows only | Windows, macOS, Linux, WSL |
| **Scanners** | 25 | 25 | 25 |
| **Update** | Recompile | Rebuild .exe | git pull |


## Output Formats

### CLI Table (default)

```
+-+-+-+-+-+-+-+
|N|e|t|w|r|i|x|
+-+-+-+-+-+-+-+
    ___    ______  __                      __          / \__
   /   |  /  _/ / / /___  __  ______  ____/ /         (    @\___
  / /| |  / // /_/ / __ \/ / / / __ \/ __  /          /         O
 / ___ |_/ // __  / /_/ / /_/ / / / / /_/ /          /   (_____/
/_/  |_/___/_/ /_/\____/\__,_/_/ /_/\__,_/          /_____/   U

  AI Credential & Secrets Scanner      Written by DFIRDeferred
  For authorized use only. Use on systems you own or have permission to test.

Tool             Credential Type        Storage      Location                            Risk
-------------------------------------------------------------------------------------------------
Claude Code CLI  oauth_access_token     plaintext... ~/.claude/.credentials.json          CRITICAL
                   Value: sk-ant-oat01-Z...eAAA
                   Note: File last modified: 2 hours ago
                   Perms: 0600 (owner-only) Owner: ull
                   Fix: Restrict file permissions: chmod 600 ~/.claude/.credentials.json

Summary: 2 findings | 1 CRITICAL | 1 HIGH
```

In verbose mode (`-v`), each finding includes:
- `Last modified:` — when the credential file was last touched, with human-readable staleness ("3 hours ago", "45 days ago")
- `Fix:` — actionable remediation guidance specific to the finding

### HTML Report (`--html-file`)

Self-contained HTML file with the AIHound banner, dark theme, color-coded risk badges, and a sortable findings table. Permissions are shown with human-readable descriptions like `0777 (world-writable, world-readable, DANGEROUS)`.

### JSON Report (`--json` or `--json-file`)

Machine-readable output with full metadata — timestamps, platform info, risk summaries, and per-finding details.

## Risk Levels

| Level | Meaning | Example |
|---|---|---|
| **CRITICAL** | Plaintext + world-readable, unauthenticated network exposure, or empty auth token | `0777` credential file; Ollama/Jupyter API on `0.0.0.0`; empty `c.NotebookApp.token = ''` |
| **HIGH** | Plaintext + user-readable only, or dangerous server config | `0600` credential file; `OLLAMA_HOST=0.0.0.0` in systemd; known API key prefix in PowerShell history |
| **MEDIUM** | OS credential store, env var, or encrypted DB | Keychain, Credential Manager, `$ANTHROPIC_API_KEY`, Firefox sessionStorage |
| **LOW** | Encrypted or not present | VS Code encrypted SQLite storage |
| **INFO** | Metadata only, no secret value | Env var reference `${GITHUB_TOKEN}`, `credsStore` pointing to a credential helper, Chromium browser detected (not parseable) |

## Adding a New Scanner

Create a new file in `aihound/scanners/` with a class that extends `BaseScanner`:

```python
from aihound.core.scanner import BaseScanner, ScanResult
from aihound.scanners import register

@register
class MyToolScanner(BaseScanner):
    def name(self) -> str:
        return "My AI Tool"

    def slug(self) -> str:
        return "my-tool"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        # Check file paths, parse configs, report findings
        ...
```

The `@register` decorator auto-discovers it. No other files need editing.

See `Full-Technical-Doc.md` for complete technical reference — every scanner's paths, detection logic, storage types, and remediation strings documented in detail.


## MCP Server Mode (v3.0.0)

### What is this?

MCP (Model Context Protocol) is a standard way for AI assistants like Claude to call external tools. When AIHound runs as an MCP server, AI assistants like **Claude Desktop**, **Claude Code**, **Cursor**, or **Windsurf** can directly scan your machine for credentials and even help you fix problems — all from inside a normal chat conversation.

You'll be able to ask the AI things like:
> "Scan my machine for exposed AI credentials and tell me what to fix."

The AI will run AIHound's scanners, read the results, and walk you through (or apply) the fixes.

### Quick mental model — important

You will **NOT** run AIHound yourself in a terminal. The AI assistant (Claude Desktop, etc.) automatically starts AIHound in the background whenever it needs to scan. You configure it once, then forget about it. **No terminal stays open.**

---

### Don't want to install Python? (Windows-only shortcut)

If you're on Windows and want the absolute easiest path, **skip Steps 1 and 2** and use the prebuilt `aihound.exe` directly. The shipped `.exe` already has MCP support baked in — no Python, no pip, nothing else to install.

1. Get the `.exe` from `pyinstaller/dist/aihound.exe` in this repo (or build it yourself with the instructions in [Section 3 above](#3-pyinstaller-windows-executable)).
2. Put it somewhere stable, e.g. `C:\Tools\aihound.exe`.
3. Skip ahead to [Step 3](#step-3-pick-your-ai-assistant-and-configure-it) — but in every config snippet below, replace:
   ```json
   "command": "aihound",
   "args": ["--mcp"]
   ```
   with:
   ```json
   "command": "C:\\Tools\\aihound.exe",
   "args": ["--mcp"]
   ```
   (Use the actual path where you saved the `.exe`. Windows JSON requires double-backslashes.)

That's it for the .exe path. Skip ahead to Step 3.

If you'd rather use Python, continue below.

### Step 1: Install Python (skip if you already have it)

Check if Python 3.10 or newer is installed by opening a terminal (Command Prompt on Windows, Terminal on macOS/Linux) and running:

```
python --version
```

If you see `Python 3.10.x` or higher, skip to Step 2.

If not, download and install Python from:
- **All platforms:** https://www.python.org/downloads/
- During the Windows installer, **check the box "Add Python to PATH"** at the bottom of the first screen — this is critical.

Verify after install by opening a new terminal and running `python --version` again.

### Step 2: Install AIHound with MCP support

In your terminal, run:

```
cd AIHound
pip install .[mcp]
```
Or if you want to install it in editable/dev mode:
```
 pip install -e .[mcp]
```

This installs both AIHound and the `mcp` Python SDK that lets AI assistants talk to it.

Verify it worked:
```
aihound --version
```

You should see `aihound 3.0.0`.

If `aihound` is not found, try `python -m aihound --version` instead. If that works, use `python -m aihound` everywhere this guide says `aihound`.

### Step 3: Pick your AI assistant and configure it

Skip to the section for the AI assistant you use:
- [Claude Desktop](#claude-desktop-setup)
- [Claude Code](#claude-code-setup)
- [Cursor](#cursor-setup)
- [Windsurf](#windsurf-setup)

---

### Claude Desktop setup

**Download Claude Desktop** if you don't have it: https://claude.ai/download

**1. Find the config file location:**
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
  - Paste that into File Explorer's address bar to open it.
- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
  - In Finder, press `Cmd+Shift+G` and paste the path.

**2. Open the file in any text editor** (Notepad, TextEdit, VS Code, etc.).

If the file doesn't exist yet, create it. If it has content already, you'll merge — don't overwrite.

**3. Make the file look like this:**

```json
{
  "mcpServers": {
    "aihound": {
      "command": "aihound",
      "args": ["--mcp"]
    }
  }
}
```

If the file already had a `"preferences"` block (or anything else), keep it and add the `"mcpServers"` block alongside:

```json
{
  "preferences": { ...whatever was there... },
  "mcpServers": {
    "aihound": {
      "command": "aihound",
      "args": ["--mcp"]
    }
  }
}
```

There's a ready-to-copy version at `examples/mcp-configs/claude-desktop.json` in this repo.

**4. Save the file and fully quit Claude Desktop.** Closing the window is not enough:
- Windows: Right-click the Claude icon in the system tray → Quit
- macOS: `Cmd+Q` from the Claude window

**5. Reopen Claude Desktop.** No terminal opens — it manages AIHound silently in the background.

**6. Verify** — start a new conversation and ask:
> List all the AIHound scanners and tell me what each one checks for.

You should see the AI invoke a tool (usually shown with a special icon) and then list 25 scanners. If it does, you're done.

---

### Claude Code setup

If you're using Claude Code, the easiest install is one command (run in any terminal):

```
claude mcp add aihound -- aihound --mcp
```

That's it. Quit and restart Claude Code (or just `/exit` and reopen). In a new conversation, ask:
> List all the AIHound scanners.

You should see the AI use the tool and report 25 scanners.

**Alternative — share with teammates via repo:** copy `examples/mcp-configs/claude-code.json` to the project root, renamed to `.mcp.json`:

```
cp examples/mcp-configs/claude-code.json .mcp.json
```

Anyone who clones the repo and opens it in Claude Code will be prompted to enable AIHound automatically. No extra setup needed.

---

### Cursor setup

**1. Find or create the config file:**
- **For just yourself across all projects:** `~/.cursor/mcp.json`
  - On Windows: `%USERPROFILE%\.cursor\mcp.json`
- **For a specific project (committed to repo):** `.cursor/mcp.json` in the project root

**2. Put this content in the file:**

```json
{
  "mcpServers": {
    "aihound": {
      "command": "aihound",
      "args": ["--mcp"]
    }
  }
}
```

There's a ready-to-copy version at `examples/mcp-configs/cursor.json`.

**3. Restart Cursor** (Cmd/Ctrl+Q to fully quit, then reopen).

**4. Verify** — open Cursor's AI chat panel and ask:
> List all the AIHound scanners.

---

### Windsurf setup

**1. Find or create the config file:** `~/.codeium/windsurf/mcp_config.json`

On Windows: `%USERPROFILE%\.codeium\windsurf\mcp_config.json`

**2. Put this content in the file:**

```json
{
  "mcpServers": {
    "aihound": {
      "command": "aihound",
      "args": ["--mcp"]
    }
  }
}
```

There's a ready-to-copy version at `examples/mcp-configs/windsurf.json`.

**3. Restart Windsurf.**

**4. Verify** — in the Cascade chat panel, ask:
> List all the AIHound scanners.

---

### What you can do once it's set up

Just talk to the AI naturally. Some examples:

> "Scan my machine for exposed AI credentials."
>
> "Are there any CRITICAL findings I should know about?"
>
> "Walk me through how to fix everything CRITICAL."
>
> "Just check my Claude Code credentials, don't scan everything."

The AI handles the tool calls behind the scenes. You see the results in plain English.

### Troubleshooting

**The AI doesn't seem to know about AIHound.**
- Did you fully quit and restart the AI client? Closing the window is usually not enough.
- Open a terminal and run `aihound --mcp` directly — it should hang waiting for input (press `Ctrl+C` to stop). If it errors with "MCP server mode requires the `mcp` Python SDK", re-run Step 2.

**`aihound: command not found`**
- Either Python isn't on your PATH, or pip installed `aihound` somewhere PATH doesn't see.
- Try the alternative form in your config — replace `"command": "aihound"` with `"command": "python"` and add `"args": ["-m", "aihound", "--mcp"]`.

**Where to find logs if something is broken:**
- **Claude Desktop:** `%APPDATA%\Claude\logs\mcp.log` (Windows) or `~/Library/Logs/Claude/mcp.log` (macOS)
- **Claude Code:** run `claude mcp list` — shows status (✓ Connected / ✗ Failed)
- **Cursor / Windsurf:** check the app's developer console / output panel

**Rebuilding after AIHound updates:**
- Just re-run `pip install --upgrade aihound[mcp]`. The AI client picks up the new version automatically next time it starts AIHound.

### Power-user variants

For non-default setups (running AIHound from source without pip install, using a specific Python interpreter, using the PyInstaller `.exe` on Windows), see [`examples/mcp-configs/README.md`](examples/mcp-configs/README.md).

### Exposed tools

| Tool | Purpose |
|------|---------|
| `aihound_scan` | Run a full scan. Args: `tools?`, `min_risk?`, `force?`. Returns findings with opaque `finding_id`, `value_preview` (masked), `remediation`, `remediation_hint` |
| `aihound_list_scanners` | Enumerate the 25 scanners and their platform applicability |
| `aihound_get_remediation` | Fetch remediation details by `finding_id` — the structured hint dict plus the human-readable string |
| `aihound_check` | Run one specific scanner by slug (bypasses cache) |

### Resources (passive reads)

| Resource URI | Contents |
|--------------|----------|
| `aihound://findings/latest` | Most recent cached scan as JSON |
| `aihound://platform` | Detected OS + WSL status + AIHound version |

### `remediation_hint` schema

Every file-based finding carries a structured `remediation_hint` dict an AI can parse and execute. Examples:

```json
{"action": "chmod", "args": ["600", "/home/u/.claude/.credentials.json"]}
{"action": "migrate_to_env", "env_vars": ["OPENAI_API_KEY"], "source": "/home/u/.openai/api_key"}
{"action": "change_config_value", "target": "bind_address", "new_value": "127.0.0.1", "service": "ollama", "port": 11434}
{"action": "run_command", "shell": "powershell", "commands": ["Remove-Item (Get-PSReadLineOption).HistorySavePath"]}
{"action": "use_credential_helper", "tool": "docker", "helper_options": ["osxkeychain", "pass", "secretservice"]}
```

Seven action types: `chmod`, `migrate_to_env`, `change_config_value`, `run_command`, `use_credential_helper`, `rotate_credential`, `manual`.

### Security model

- **Read-only server.** AIHound never modifies files over MCP. If the assistant wants to fix something, it uses its own filesystem tools.
- **Raw credential values never leave the process.** MCP responses contain `value_preview` (masked) only — regardless of any flag. The `raw_value` field is unconditionally stripped.
- **stdio transport only.** No network exposure. The MCP client spawns AIHound as a subprocess.

### End-to-end example (asking Claude Desktop)

> You: "Scan my system for AI credential exposure and fix anything CRITICAL."
>
> Claude: calls `aihound_scan(min_risk="critical")` → gets back 4 findings with `remediation_hint` dicts → reads each hint → runs `chmod 600 ~/.claude/.credentials.json` via its filesystem tool → calls `aihound_scan(force=True)` to verify → reports back.


## Project Structure

```
aihound/
├── core/
│   ├── scanner.py       # BaseScanner, CredentialFinding, ScanResult, enums
│   ├── platform.py      # OS detection (Linux/macOS/Windows/WSL), path resolution
│   ├── redactor.py      # Secret masking with known prefix detection
│   ├── permissions.py   # File permission analysis + human-readable descriptions
│   └── mcp.py           # Shared MCP config parser (used by multiple scanners)
├── scanners/            # One file per tool, auto-discovered via @register
├── output/
│   ├── table.py         # CLI table with ANSI colors
│   ├── json_export.py   # JSON report
│   └── html_report.py   # Self-contained HTML report with embedded banner
└── utils/
    ├── keychain.py      # macOS Keychain queries
    ├── credman.py       # Windows Credential Manager queries
    └── vscdb.py         # VS Code SQLite state.vscdb reader
```

## Security & Ethics

This tool is for **authorized security research, penetration testing, and defensive security assessments only**. Use it on systems you own or have explicit authorization to test.

- Credentials are **redacted by default** — `--show-secrets` requires explicit `YES` confirmation
- The tool is **read-only** — it never modifies, exfiltrates, or transmits any credentials
- JSON output **never includes raw values** even with `--show-secrets`


---

## License

MIT
