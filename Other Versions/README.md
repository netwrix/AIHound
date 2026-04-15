# AIHound Build & Run Guide

AIHound can be run three ways: from Python source, as a compiled Go binary, or as a standalone Windows executable (via PyInstaller).

---

## 1. Python Source (Original)

### Prerequisites
- Python 3.10+
- pip

### Install
```bash
pip install -r requirements.txt
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

### Available Scanners

| Slug | Tool |
|------|------|
| `amazon-q` | Amazon Q / AWS |
| `chatgpt` | ChatGPT Desktop |
| `claude-code` | Claude Code CLI |
| `claude-desktop` | Claude Desktop |
| `cline` | Cline (VS Code) |
| `continue-dev` | Continue.dev |
| `cursor` | Cursor IDE |
| `envvars` | Environment Variables |
| `gemini` | Gemini CLI / GCloud |
| `github-copilot` | GitHub Copilot |
| `lm-studio` | LM Studio |
| `ollama` | Ollama |
| `openclaw` | OpenClaw |
| `windsurf` | Windsurf |

---

## Comparison

| | Go Binary | PyInstaller .exe | Python Source |
|---|---|---|---|
| **Size** | ~5.5 MB | ~14 MB | N/A (needs Python) |
| **Startup** | Instant | ~1-5s (extract, varies with AV) | Instant |
| **Runtime Dependencies** | None | None | Python 3.10+ |
| **Cross-Compile** | Yes (any OS to any OS) | No (must build on Windows) | N/A |
| **Supported Platforms** | Windows, macOS, Linux, WSL | Windows only | Windows, macOS, Linux, WSL |
| **Update** | Recompile | Rebuild .exe | git pull |
| **Version** | 0.2.0 | 0.1.0 (matches Python) | 0.1.0 |
