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

---

## CLI Reference

All flags are the same across all three versions:

| Flag | Description |
|------|-------------|
| `--version` | Show version and exit |
| `--show-secrets` | Display actual credential values (requires interactive "YES" confirmation) |
| `--json` | Output JSON to stdout |
| `--json-file PATH` | Write JSON report to file |
| `--html-file PATH` | Write HTML report to file |
| `--banner PATH` | Custom banner image for HTML report |
| `--tools TOOL ...` | Only scan specified tools (by slug) |
| `--list-tools` | List all available scanners |
| `-v`, `--verbose` | Show debug output, permissions, and stack traces |
| `--no-color` | Disable ANSI color codes |

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

## License

MIT
