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
- **API keys** (OpenAI, Anthropic, Google, AWS, Hugging Face, etc.)
- **MCP server secrets** — inline tokens, auth headers, and credentials embedded in MCP configurations
- **AWS credentials** — access keys, secret keys, session tokens, SSO cache
- **Google Cloud ADC** — application default credentials, service account keys
- **Local AI server exposure** — detects Ollama and LM Studio servers listening on all interfaces without authentication
- **Environment variables** — 35+ known AI-related env vars
- **Plaintext config files** — `.env` files, JSON configs with hardcoded secrets

## Supported Tools

| Tool | What's Scanned |
|---|---|
| **Claude Code CLI** | `~/.claude/.credentials.json`, `~/.claude.json` MCP config, Keychain |
| **Claude Desktop** | `claude_desktop_config.json`, MCP server env vars & headers |
| **GitHub Copilot** | Keychain/Credential Manager, `~/.copilot/config.json`, VS Code storage |
| **Cursor IDE** | `~/.cursor/mcp.json`, app config directories |
| **Continue.dev** | `~/.continue/config.json` (plaintext API keys) |
| **Cline** | `cline_mcp_settings.json` (plaintext MCP creds) |
| **Windsurf** | `~/.codeium/windsurf/` config and MCP settings |
| **ChatGPT Desktop** | App data directories (macOS & Windows) |
| **Ollama** | `~/.ollama/`, env vars, systemd service, network exposure (port 11434) |
| **LM Studio** | App config dirs, HF tokens, `.env` files, network exposure (port 1234) |
| **Amazon Q / AWS** | `~/.aws/credentials`, SSO cache tokens |
| **Gemini CLI / GCloud** | `.env` files, application default credentials |
| **Environment Variables** | 35+ AI-related env vars (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, etc.) |

## Platform Support

| Platform | Status |
|---|---|
| **Linux** | Full support |
| **macOS** | Full support (includes Keychain queries) |
| **Windows** | Full support (includes Credential Manager) |
| **WSL** | Full support — scans **both** Linux paths and Windows paths via `/mnt/c/` |

## Installation

```bash
# Clone the repo
git clone https://github.com/dfirdeferred/aihound.git
cd aihound

# Run directly (zero dependencies for core scanning)
python3 -m aihound

# Optional: install rich for colored table output
pip install rich
```

## Usage

```bash
# Basic scan — all tools, redacted output
python3 -m aihound

# Verbose mode — show permissions, notes, expiry info
python3 -m aihound -v

# Generate HTML report
python3 -m aihound --html-file report.html

# Generate JSON report
python3 -m aihound --json-file report.json

# JSON to stdout (for piping)
python3 -m aihound --json

# Scan specific tools only
python3 -m aihound --tools claude-code envvars

# List all available scanners
python3 -m aihound --list-tools

# Show actual secret values (requires confirmation)
python3 -m aihound --show-secrets

# Combine outputs
python3 -m aihound -v --html-file report.html --json-file report.json
```

## Output Formats

### CLI Table (default)

```
╔══════════════════════════════════════════════════════════════╗
║          AIHound - AI Credential & Secrets Scanner           ║
╚══════════════════════════════════════════════════════════════╝

Tool             Credential Type        Storage      Location                            Risk
-------------------------------------------------------------------------------------------------
Claude Code CLI  oauth_access_token     plaintext... ~/.claude/.credentials.json          CRITICAL
                   Value: sk-ant-oat01-Z...eAAA
Claude Code CLI  oauth_refresh_token    plaintext... ~/.claude/.credentials.json          HIGH
                   Value: sk-ant-ort01-j...8AAA

Summary: 2 findings | 1 CRITICAL | 1 HIGH
```

### HTML Report (`--html-file`)

Self-contained HTML file with the AIHound banner, dark theme, color-coded risk badges, and a sortable findings table. Permissions are shown with human-readable descriptions like `0777 (world-writable, world-readable, DANGEROUS)`.

### JSON Report (`--json` or `--json-file`)

Machine-readable output with full metadata — timestamps, platform info, risk summaries, and per-finding details.

## Risk Levels

| Level | Meaning | Example |
|---|---|---|
| **CRITICAL** | Plaintext + world-readable, or unauthenticated network exposure | `0777` credential file; Ollama API on `0.0.0.0` |
| **HIGH** | Plaintext + user-readable only, or dangerous server config | `0600` credential file; `OLLAMA_HOST=0.0.0.0` in systemd |
| **MEDIUM** | OS credential store or env var | Keychain, Credential Manager, `$ANTHROPIC_API_KEY` |
| **LOW** | Encrypted or not present | VS Code encrypted SQLite storage |
| **INFO** | Metadata only, no secret value | Env var reference `${GITHUB_TOKEN}`, config flags |

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
