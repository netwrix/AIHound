# AIHound - Full Technical Reference

A comprehensive technical reference for AIHound, an AI credential and secrets scanner. This document describes every scanner, what it checks, where it checks, and how findings are classified. It is a living document — add new sections as the tool evolves.

**Current version:** 0.1.0
**Scanner count:** 25
**Supported platforms:** Windows, macOS, Linux, WSL (Windows Subsystem for Linux)

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Core Data Types](#core-data-types)
4. [Platform Detection](#platform-detection)
5. [Credential Redaction](#credential-redaction)
6. [Risk Assessment](#risk-assessment)
7. [MCP Config Parser](#mcp-config-parser)
8. [CLI Interface](#cli-interface)
9. [Output Formats](#output-formats)
10. [Scanner Reference](#scanner-reference)
11. [Common Patterns](#common-patterns)

---

## Overview

AIHound scans a system for credentials and secrets belonging to AI tools, developer tools, and AI infrastructure. It identifies where credentials are stored, how they're protected, and what risk they pose based on file permissions, storage type, and context.

**Design principles:**
- Read-only: never modifies, exfiltrates, or transmits credentials
- Redacted by default: actual credential values are hidden unless `--show-secrets` is used (with interactive confirmation)
- Zero core dependencies: pure Python stdlib for scanning; `rich` is optional for table formatting
- Cross-platform: same codebase runs on Windows, macOS, Linux, and WSL
- Extensible: scanners are auto-discovered plugins; adding a scanner is one new file

**Three distributions:**
1. Python source (`python -m aihound`)
2. Go binary (`Go/` directory, cross-compilable static binary)
3. PyInstaller Windows executable (`pyinstaller/dist/aihound.exe`)

---

## Architecture

```
aihound/
├── core/
│   ├── scanner.py      # Base classes, enums, data models
│   ├── platform.py     # OS detection, path resolution, WSL dual-scan
│   ├── redactor.py     # Credential masking with known prefix table
│   ├── permissions.py  # File permission analysis + risk assessment
│   └── mcp.py          # Shared MCP config parser (used by 5 scanners)
├── scanners/           # 25 scanner plugins, auto-discovered via @register
│   ├── __init__.py     # Scanner registry (pkgutil.iter_modules discovery)
│   └── <scanner>.py    # One file per scanner
├── output/
│   ├── table.py        # ANSI-colored terminal table with banner
│   ├── json_export.py  # JSON report with metadata + summary
│   └── html_report.py  # Self-contained HTML dashboard
├── utils/
│   ├── keychain.py     # macOS Keychain access (via `security` CLI)
│   ├── credman.py      # Windows Credential Manager (via ctypes)
│   └── vscdb.py        # VS Code state.vscdb SQLite reader
├── cli.py              # CLI entry point (argparse)
├── __main__.py         # `python -m aihound` entry point
└── __init__.py         # Version string
```

**Scanner registration:** Each scanner class is decorated with `@register`. The `scanners/__init__.py` module uses `pkgutil.iter_modules` to auto-discover and import all scanner files, which triggers the decorator registration. No manual registration is required.

---

## Core Data Types

### `StorageType` enum

Describes how a credential is stored:

| Value | Meaning |
|-------|---------|
| `PLAINTEXT_JSON` | Unencrypted JSON file |
| `PLAINTEXT_YAML` | Unencrypted YAML file |
| `PLAINTEXT_ENV` | Unencrypted `.env` file |
| `PLAINTEXT_INI` | Unencrypted INI/config file |
| `PLAINTEXT_FILE` | Unencrypted plain text file (e.g., single-line token files) |
| `KEYCHAIN` | macOS Keychain |
| `CREDENTIAL_MANAGER` | Windows Credential Manager |
| `ENCRYPTED_DB` | SQLite or browser database |
| `ENVIRONMENT_VAR` | Environment variable |
| `UNKNOWN` | Cannot determine |

### `RiskLevel` enum

| Level | Criteria |
|-------|----------|
| `CRITICAL` | Plaintext + world-readable, OR unauthenticated network service, OR empty Jupyter token |
| `HIGH` | Plaintext + user-readable only, OR OS credential store, OR dangerous network config |
| `MEDIUM` | OS keychain (extractable with user access), environment variable, encrypted DB |
| `LOW` | Encrypted storage |
| `INFO` | Metadata only, no credential value exposed |

### `CredentialFinding` dataclass

Core finding structure:

| Field | Type | Description |
|-------|------|-------------|
| `tool_name` | str | Tool/platform the credential belongs to |
| `credential_type` | str | Type identifier (e.g., "oauth_access_token", "api_key") |
| `storage_type` | StorageType | How it's stored |
| `location` | str | File path (optionally with `:line_number`) or env var name |
| `exists` | bool | Whether the credential was actually found |
| `risk_level` | RiskLevel | Severity assessment |
| `value_preview` | Optional[str] | Masked value for display |
| `raw_value` | Optional[str] | Unmasked value (only populated if `--show-secrets`) |
| `file_permissions` | Optional[str] | Octal string (e.g., `"0600"`) |
| `file_owner` | Optional[str] | Username or UID |
| `expiry` | Optional[datetime] | When the credential expires (if known) |
| `notes` | list[str] | Additional context (staleness, line numbers, confidence, etc.) |
| `file_modified` | Optional[datetime] | When the file was last modified |
| `remediation` | Optional[str] | Actionable guidance on how to fix |

Raw values are **never** included in JSON export regardless of `--show-secrets`.

### `ScanResult` dataclass

One per scanner invocation:

| Field | Type | Description |
|-------|------|-------------|
| `scanner_name` | str | Name of the scanner |
| `platform` | str | Detected platform (`windows`, `macos`, `linux`, `wsl`) |
| `findings` | list[CredentialFinding] | Discovered credentials |
| `errors` | list[str] | Non-fatal errors encountered during scanning |
| `scan_time` | float | Execution time in seconds |

### `BaseScanner` abstract class

All scanners subclass this:

| Method | Description |
|--------|-------------|
| `name()` → str | Human-readable name (abstract) |
| `slug()` → str | CLI-friendly identifier (abstract) |
| `scan(show_secrets)` → ScanResult | Main scanning logic (abstract) |
| `is_applicable()` → bool | Returns False if scanner doesn't apply to current platform (default: True) |
| `run(show_secrets)` → ScanResult | Wraps `scan()` with timing and error handling |

---

## Platform Detection

### `Platform` enum

- `WINDOWS` — Native Windows
- `MACOS` — macOS / Darwin
- `LINUX` — Native Linux (not WSL)
- `WSL` — Windows Subsystem for Linux

### Detection logic (`core/platform.py`)

- `detect_platform()` — cached result; uses `sys.platform` plus `/proc/version` content check for WSL ("microsoft" substring)
- `get_home()` — user home directory (`Path.home()`)
- `get_appdata()` — Windows `%APPDATA%`, resolvable from WSL via `$APPDATA` env var or explicit Windows path
- `get_localappdata()` — Windows `%LOCALAPPDATA%`, similarly resolvable from WSL
- `get_wsl_windows_home()` — Windows user's home when running under WSL (e.g., `/mnt/c/Users/<user>`)
- `get_xdg_config()` — `$XDG_CONFIG_HOME` with fallback to `~/.config`
- `resolve_paths_for_tool()` — utility that builds cross-platform path lists from templates

### WSL dual-scan behavior

On WSL, scanners check **both** Linux-native paths (e.g., `~/.claude/`) **and** Windows-side paths (e.g., `/mnt/c/Users/<user>/.claude/`). This produces complete coverage of all credentials visible from the WSL environment.

---

## Credential Redaction

### Known prefix table (`core/redactor.py`)

| Prefix | Provider |
|--------|----------|
| `sk-ant-` | Anthropic |
| `sk-ant-ort` | Anthropic Refresh Token |
| `sk-ant-oat` | Anthropic Access Token |
| `sk-` | OpenAI / Generic |
| `ghp_` | GitHub PAT (classic) |
| `gho_` | GitHub OAuth |
| `ghu_` | GitHub User-to-Server |
| `ghs_` | GitHub Server-to-Server |
| `github_pat_` | GitHub PAT (fine-grained) |
| `xoxb-` | Slack Bot Token |
| `xoxp-` | Slack User Token |
| `xoxa-` | Slack App Token |
| `AKIA` | AWS Access Key |
| `AIza` | Google API Key |
| `ya29.` | Google OAuth Access Token |

Prefix matching is **longest-first** so `sk-ant-oat` takes precedence over `sk-ant-`.

### Masking logic

`mask_value(value, show_full=False)`:

- If `show_full=True`: returns value unchanged
- If length ≤ 8: returns `***REDACTED***`
- If matches a known prefix: `<prefix><first N chars>...<last 4>` (e.g., `sk-ant-oat01-abc...xF2q`)
- If no match: `<first 6>...<last 4>` (e.g., `abcd12...ef89`)

### `identify_credential_type(value)`

Returns the human-readable credential type from the prefix table, or `None`.

---

## Risk Assessment

### `assess_risk(storage_type, path)` logic (`core/permissions.py`)

| Storage type | Conditions | Risk |
|--------------|-----------|------|
| `ENVIRONMENT_VAR` | — | MEDIUM |
| `KEYCHAIN`, `CREDENTIAL_MANAGER`, `ENCRYPTED_DB` | — | MEDIUM |
| Plaintext (JSON/YAML/ENV/INI/FILE) | World-readable | CRITICAL |
| Plaintext | Group-readable (not world) | HIGH |
| Plaintext | Owner-only | HIGH |
| Other | — | INFO |

Some scanners **override** this baseline for scanner-specific risks:
- Network exposure scanner bumps to CRITICAL for `0.0.0.0` bindings
- Jupyter scanner bumps to CRITICAL for empty tokens (unauthenticated server)
- PowerShell scanner bumps known-prefix matches to HIGH at minimum

### Permission helpers

| Function | Returns |
|----------|---------|
| `get_file_permissions(path)` | Octal string (e.g., `"0600"`) |
| `get_file_owner(path)` | Username or UID as string |
| `is_world_readable(path)` | bool — `stat.S_IROTH` bit check |
| `is_group_readable(path)` | bool — `stat.S_IRGRP` bit check |
| `describe_permissions(perms)` | Human-readable string (e.g., `"owner-only, world-readable"`) |
| `get_file_mtime(path)` | UTC datetime |
| `describe_staleness(mtime)` | Human-readable (e.g., `"3 hours ago"`, `"45 days ago"`) |

---

## MCP Config Parser

### `core/mcp.py`

Used by 5 scanners: Claude Desktop, Claude Code, Cursor, Cline, Windsurf.

### Secret key patterns

Any key name containing one of these substrings (case-insensitive) is treated as a potential secret location:
- `token`, `key`, `secret`, `password`, `passwd`, `auth`, `credential`, `cred`, `api_key`, `apikey`, `access_key`, `bearer`, `jwt`

### Scan locations within each `mcpServers` entry

1. **`env` block** — environment variables passed to the server
2. **`headers` block** — HTTP authentication headers (`Authorization`, `X-API-Key`, `API-Key`)
3. **`args` array** — CLI arguments to the server process

### Detection logic

For each matching key:
- If value contains `${VAR}` syntax → INFO finding (external reference, not an inline secret)
- If value matches the inline-secret heuristic → HIGH/CRITICAL based on file permissions
  - **Heuristic:** length ≥ 20, alphanumeric ratio ≥ 80%, does not start with `/` or `http`

### Remediation strings

- Inline secrets: `"Move secret to environment variable or secret manager"`
- Env-var references: `"Verify env var is set in a secure environment, not committed to source"`

---

## CLI Interface

### Flags (`aihound/cli.py`)

| Flag | Description |
|------|-------------|
| `--version` | Show version (`aihound 0.1.0`) and exit |
| `--show-secrets` | Display raw credential values (gated with interactive "YES" confirmation) |
| `--json` | Output JSON to stdout |
| `--json-file PATH` | Write JSON report to file |
| `--html-file PATH` | Write HTML report to file |
| `--banner PATH` | Custom banner image for HTML report |
| `--tools TOOL [TOOL ...]` | Scan only specified tools (by slug) |
| `--list-tools` | List all available scanners with applicability |
| `-v`, `--verbose` | Show DEBUG logging, file permissions, remediation, staleness |
| `--no-color` | Disable ANSI color codes |

### Safety gates

- `--show-secrets` checks `sys.stdin.isatty()` and requires the user to type `YES` (case-sensitive). Non-TTY sessions cannot enable this flag.
- JSON export never includes `raw_value` regardless of `--show-secrets`.
- All scanners wrap their logic in `BaseScanner.run()` which catches exceptions and reports them as errors in `ScanResult.errors` instead of crashing.

---

## Output Formats

### Table (`aihound/output/table.py`)

- ANSI color-coded by risk level (CRITICAL=red, HIGH=yellow, MEDIUM=orange, LOW=green, INFO=cyan)
- Columns: Tool, Credential Type, Storage, Location, Risk
- Verbose mode (`-v`) adds: value preview, notes, permissions, owner, `Last modified:`, `Fix:` (remediation)
- Summary line with counts by risk level
- Banner: Netwrix logo + AIHound ASCII art + running hound + disclaimer + `Written by DFIRDeferred`

### JSON Export (`aihound/output/json_export.py`)

Structure:
```json
{
  "scan_metadata": {
    "timestamp": "<UTC ISO8601>",
    "platform": "<wsl|linux|macos|windows>",
    "aihound_version": "0.1.0"
  },
  "findings": [ {...CredentialFinding as dict...} ],
  "errors": [ "..." ],
  "summary": {
    "total_findings": N,
    "by_risk": { "critical": N, "high": N, ... }
  }
}
```

Each finding includes all fields except `raw_value`. The `file_modified` field serializes as ISO 8601.

### HTML Report (`aihound/output/html_report.py`)

- Dark theme, self-contained single file
- Color-coded risk badges (red/yellow/orange/green/gray)
- Sortable findings table with sticky header
- Embedded banner image (base64)
- CSS styles for:
  - `.remediation` (green italic) — fix guidance
  - `.file-modified` (gray, small) — staleness info
  - `.note`, `.perms`, `.expiry` — supporting details
- Platform, scan time, summary stats in header

---

## Scanner Reference

### 1. Aider (`aider`)

**What it scans:** Aider CLI config files for inline API keys.

| Platform | Paths |
|----------|-------|
| All | `~/.aider.conf.yml`, `~/.aider.conf.yaml` |
| WSL | Also Windows `%USERPROFILE%/.aider.conf.yml` |

**Detection:** Line-by-line YAML parsing. Flags any key containing `key`, `token`, `secret`, `password`, `passwd`, `auth`, `credential`. Strips comments and surrounding quotes; skips boolean values.

**Storage:** `PLAINTEXT_YAML`

**Remediation:** `"Use environment variables (OPENAI_API_KEY, ANTHROPIC_API_KEY) instead of config file"`

---

### 2. Amazon Q / AWS (`amazon-q`)

**What it scans:** AWS credentials file and SSO token cache.

| Platform | Paths |
|----------|-------|
| All | `~/.aws/credentials`, `~/.aws/sso/cache/*.json` |
| WSL | Also Windows `%USERPROFILE%/.aws/...` |

**Detection:**
- `credentials`: INI parser for `aws_access_key_id`, `aws_secret_access_key`, `aws_session_token` per profile section
- `sso/cache/*.json`: extracts `accessToken` field

**Storage:** `PLAINTEXT_INI` (credentials), `PLAINTEXT_JSON` (SSO cache)

**Remediation:** `"Use AWS SSO or IAM roles instead of long-lived access keys"` / `"Rotate SSO tokens regularly"`

---

### 3. Browser Sessions (`browser-sessions`)

**What it scans:** Browser localStorage and cookies for AI tool session tokens.

**Firefox (SQLite):**

| Platform | Profile dir |
|----------|-------------|
| Linux/WSL | `~/.mozilla/firefox/` |
| macOS | `~/Library/Application Support/Firefox/Profiles/` |
| Windows | `%APPDATA%/Mozilla/Firefox/Profiles/` |

Parses `profiles.ini` to enumerate profiles. Opens `webappsstore.sqlite` and `cookies.sqlite` read-only (`mode=ro`, `timeout=1`). Graceful fallback if DB is locked.

**AI domains tracked:** `claude.ai`, `openai.com`, `chatgpt.com`, `gemini.google.com`, `copilot.microsoft.com`, `perplexity.ai`, `huggingface.co`

**Chromium (Chrome, Brave, Edge):** LevelDB format is not parseable without external dependencies. Detects the Local Storage directories and reports one INFO finding per browser noting that storage exists but cannot be parsed.

**Storage:** `ENCRYPTED_DB`

**Risk:** MEDIUM (Firefox), INFO (Chromium stub)

**Remediation:** `"Ensure browser profile directory has restricted permissions (chmod 700). Clear site data to revoke local sessions."`

---

### 4. ChatGPT Desktop (`chatgpt`)

**What it scans:** OpenAI ChatGPT desktop app data for session tokens.

| Platform | Paths |
|----------|-------|
| macOS | `~/Library/Application Support/ChatGPT`, `~/Library/Application Support/com.openai.chat` |
| Windows | `%APPDATA%/OpenAI/ChatGPT`, `%APPDATA%/com.openai.chat` |
| WSL | Windows paths via `/mnt/c/` |

**Detection:** Recursive JSON descent looking for keys: `accessToken`, `access_token`, `token`, `session_token`, `refresh_token`, `api_key`, `apiKey`.

**Storage:** `PLAINTEXT_JSON`

**Remediation:** `"Restrict file permissions on ChatGPT config directory"`

---

### 5. Claude Code CLI (`claude-code`)

**What it scans:** Claude Code CLI credentials and settings.

| Platform | Paths |
|----------|-------|
| All | `~/.claude/.credentials.json`, `~/.claude.json`, `~/.claude/settings.json` |
| WSL | Also Windows `%USERPROFILE%/.claude/` |

**Detection:**
- `.credentials.json`: recursive JSON descent for `access`/`accessToken` → `oauth_access_token`, `refresh`/`refreshToken` → `oauth_refresh_token`, `apiKey` → `api_key`, `token` → `auth_token`
- `.claude.json` and `settings.json`: MCP server config via `parse_mcp_file`
- Extracts expiry (Unix timestamp or milliseconds) and auth type annotations

**Storage:** `PLAINTEXT_JSON`

**Remediation:** `"Restrict file permissions: chmod 600 <path>"`

---

### 6. Claude Desktop (`claude-desktop`)

**What it scans:** Claude Desktop MCP server configuration.

| Platform | Paths |
|----------|-------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%/Claude/claude_desktop_config.json` |
| Linux | `~/.config/Claude/claude_desktop_config.json` |
| WSL | Both Linux and Windows paths |

**Detection:** Pure MCP parser consumer (see [MCP Config Parser](#mcp-config-parser)).

**Storage:** `PLAINTEXT_JSON`

---

### 7. Cline VS Code Extension (`cline`)

**What it scans:** Cline VS Code extension MCP settings.

| Platform | Paths |
|----------|-------|
| Linux/WSL | `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` |
| macOS | `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` |
| Windows | `%APPDATA%/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json` |

**Detection:** Pure MCP parser consumer.

**Storage:** `PLAINTEXT_JSON`

---

### 8. Continue.dev (`continue-dev`)

**What it scans:** Continue.dev config for plaintext API keys.

| Platform | Paths |
|----------|-------|
| All | `~/.continue/config.json`, `~/.continue/config.yaml` |
| WSL | Also Windows `%USERPROFILE%/.continue/` |

**Detection:**
- `models[].apiKey` per provider
- `tabAutocompleteModel.apiKey`
- Distinguishes `${VAR}` references (INFO) from inline values (HIGH/CRITICAL)

**Storage:** `PLAINTEXT_JSON`

**Remediation:** `"Use environment variables instead of inline API keys in config"`

---

### 9. Cursor IDE (`cursor`)

**What it scans:** Cursor IDE MCP server configuration.

| Platform | Paths |
|----------|-------|
| All | `~/.cursor/mcp.json` |
| macOS | `~/Library/Application Support/Cursor/User/globalStorage/mcp.json` |
| Windows | `%APPDATA%/Cursor/User/globalStorage/mcp.json` |
| Linux/WSL | `~/.config/Cursor/User/globalStorage/mcp.json` |

**Detection:** Pure MCP parser consumer.

**Storage:** `PLAINTEXT_JSON`

---

### 10. Docker (`docker`)

**What it scans:** Docker registry authentication and credential helpers.

| Platform | Paths |
|----------|-------|
| All | `~/.docker/config.json` |
| WSL | Also Windows `%USERPROFILE%/.docker/config.json` |

**Detection:**
- `auths.<registry>.auth` — base64(`user:password`) — HIGH/CRITICAL
- `auths.<registry>.identitytoken` — OAuth refresh token — HIGH/CRITICAL
- `credsStore` — credential helper name — INFO (safe storage indicator)
- `credHelpers` — per-registry helpers — INFO
- Recursive scan (max depth 4) for other secret-looking fields

**Storage:** `PLAINTEXT_JSON`

**Remediation:** `"Use docker credential helpers (credsStore) instead of storing tokens in config.json. See: docker login --help"`

---

### 11. Environment Variables (`envvars`)

**What it scans:** AI-related environment variables in the current process environment.

**Variables monitored (35+):**

| Category | Variables |
|----------|-----------|
| Anthropic | `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN`, `CLAUDE_CODE_USE_BEDROCK`, `CLAUDE_CODE_USE_VERTEX`, `CLAUDE_CODE_USE_FOUNDRY` |
| OpenAI | `OPENAI_API_KEY`, `OPENAI_ORG_ID` |
| Google | `GEMINI_API_KEY`, `GOOGLE_API_KEY`, `GOOGLE_APPLICATION_CREDENTIALS` |
| GitHub | `GITHUB_TOKEN`, `GH_TOKEN`, `GITHUB_PERSONAL_ACCESS_TOKEN`, `COPILOT_GITHUB_TOKEN` |
| AWS | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_PROFILE` |
| Azure | `ADO_MCP_AUTH_TOKEN`, `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT` |
| ML providers | `HF_TOKEN`, `HUGGING_FACE_HUB_TOKEN`, `COHERE_API_KEY`, `REPLICATE_API_TOKEN`, `TOGETHER_API_KEY`, `GROQ_API_KEY`, `MISTRAL_API_KEY`, `DEEPSEEK_API_KEY`, `XAI_API_KEY`, `PERPLEXITY_API_KEY`, `FIREWORKS_API_KEY`, `OLLAMA_API_KEY`, `LM_STUDIO_API_KEY` |

**Risk:**
- Flag vars (`USE_BEDROCK`, `USE_VERTEX`, etc.) → INFO
- File-path vars (`GOOGLE_APPLICATION_CREDENTIALS`) → MEDIUM
- Actual credentials → MEDIUM

**Storage:** `ENVIRONMENT_VAR`

**Remediation:** `"Use a secret manager instead of environment variables"`

---

### 12. Gemini CLI / Google Cloud ADC (`gemini`)

**What it scans:** Gemini CLI `.env` files and Google Cloud Application Default Credentials.

| Platform | Paths |
|----------|-------|
| All | `~/.gemini/.env`, `~/.env` |
| Linux | `~/.config/gcloud/application_default_credentials.json` |
| macOS | `~/Library/Application Support/gcloud/application_default_credentials.json` |
| Windows | `%APPDATA%/gcloud/application_default_credentials.json` |
| WSL | Both Linux and Windows paths |

**Detection:**
- `.env`: `GEMINI_API_KEY`, `GOOGLE_API_KEY`, `GOOGLE_APPLICATION_CREDENTIALS`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`
- ADC JSON: `client_secret`, `refresh_token`, `private_key` (service account)

**Storage:** `PLAINTEXT_ENV`, `PLAINTEXT_JSON`

**Remediation:** `"Use environment variables instead of .env files"` / `"Rotate Application Default Credentials regularly"`

---

### 13. Git Credentials (`git-credentials`)

**What it scans:** Git credential store and gitconfig for embedded tokens.

| Platform | Paths |
|----------|-------|
| All | `~/.git-credentials`, `~/.config/git/credentials`, `~/.gitconfig`, `~/.config/git/config` |
| WSL | Also Windows `%USERPROFILE%/.git-credentials`, `%USERPROFILE%/.gitconfig` |

**Detection:**
- `.git-credentials`: one URL per line; parses `https://user:token@host` via `urllib.parse.urlparse`
- `.gitconfig`: `configparser(strict=False)` for `[credential]` sections and `[url]` sections with embedded `user:password@` patterns

**Storage:** `PLAINTEXT_FILE` (credentials), `PLAINTEXT_INI` (gitconfig)

**Note:** Does NOT recursively scan all `.git/config` files on disk (too invasive/slow).

**Remediation:** `"Use a secure credential helper (osxkeychain, manager, libsecret) instead of plaintext store"`

---

### 14. GitHub Copilot (`github-copilot`)

**What it scans:** GitHub Copilot, GitHub CLI, and VS Code Copilot extension tokens.

| Target | Paths |
|--------|-------|
| Copilot CLI (Linux) | `~/.copilot/config.json` |
| GitHub CLI (Linux/WSL) | `~/.config/gh/hosts.yml` |
| GitHub CLI (macOS) | `~/Library/Application Support/gh/hosts.yml` |
| GitHub CLI (Windows) | `%APPDATA%/GitHub CLI/hosts.yml` |
| VS Code Copilot (Linux/WSL) | `~/.config/Code/User/globalStorage/github.copilot/hosts.json`, `~/.config/Code/User/globalStorage/github.copilot-chat/hosts.json` |
| VS Code Copilot (macOS) | `~/Library/Application Support/Code/User/globalStorage/github.copilot/hosts.json` |
| VS Code Copilot (Windows) | `%APPDATA%/Code/User/globalStorage/github.copilot/hosts.json` |

**Detection:**
- JSON: any field containing `token`, `oauth`, or `key`
- YAML: simple line-by-line parser for `oauth_token`, `token`

**Storage:** `PLAINTEXT_JSON`, `PLAINTEXT_YAML`

**Remediation:** `"Restrict file permissions: chmod 600 <path>"` / `"Use GitHub CLI (gh auth) for secure token storage"`

---

### 15. Hugging Face CLI (`huggingface`)

**What it scans:** Hugging Face CLI single-line token files.

| Platform | Paths |
|----------|-------|
| All | `~/.cache/huggingface/token`, `~/.huggingface/token` |
| WSL | Also Windows `%USERPROFILE%/.cache/huggingface/token`, `%USERPROFILE%/.huggingface/token` |

**Detection:** `path.read_text().strip()` — entire file content is the token.

**Storage:** `PLAINTEXT_FILE`

**Remediation:** `"Use HF_TOKEN environment variable instead of plaintext token file"`

---

### 16. Jupyter (`jupyter`)

**What it scans:** Jupyter Notebook/Lab configs and kernel specs.

| Platform | Config paths |
|----------|--------------|
| All | `~/.jupyter/jupyter_notebook_config.py`, `~/.jupyter/jupyter_notebook_config.json`, `~/.jupyter/jupyter_server_config.py`, `~/.jupyter/jupyter_server_config.json` |
| WSL | Also Windows `%USERPROFILE%/.jupyter/` |

| Platform | Kernel paths |
|----------|--------------|
| Linux | `~/.local/share/jupyter/kernels/*/kernel.json` |
| macOS | `~/Library/Jupyter/kernels/*/kernel.json` |
| Windows | `%APPDATA%/jupyter/kernels/*/kernel.json` |
| WSL | Both Linux and Windows |

**Detection:**
- `.py` configs: regex `c\.(NotebookApp|ServerApp|Notebook)\.(token|password)\s*=\s*['"](...)['"]`
- `.json` configs: `NotebookApp.token`, `ServerApp.token`, etc.
- `kernel.json`: scans `env` dict for secret-looking values (inline-secret heuristic)

**Special risk:** Empty token → **CRITICAL** (server accepts connections without authentication).

**Storage:** `PLAINTEXT_FILE` (Python configs), `PLAINTEXT_JSON` (JSON configs and kernels)

**Remediation:** `"Set a strong token or password hash; avoid binding to 0.0.0.0 or use an authentication proxy"` / `"Move API keys out of kernel.json env; use environment variables or secret managers"`

---

### 17. LM Studio (`lm-studio`)

**What it scans:** LM Studio configs, secrets, and network exposure.

| Platform | Paths |
|----------|-------|
| macOS | `~/Library/Application Support/LM Studio` |
| Windows | `%APPDATA%/LM Studio`, `%LOCALAPPDATA%/LM Studio` |
| Linux | `~/.config/LM Studio`, `~/.var/app/com.lmstudio.lmstudio/config/LM Studio` (Flatpak) |
| WSL | Both Linux and Windows paths |

**Detection:**
- All `*.json` in config root, `config/`, `settings/`, `auth/` subdirectories
- Secret keys: `api_key`, `apiKey`, `token`, `auth_token`, `access_token`, `hf_token`, `huggingface_token`, `password`, `secret`
- Nested structures: `huggingFace`, `huggingface`, `hf`, `auth`, `credentials` dicts
- All `*.env` files — KEY/TOKEN/SECRET/PASSWORD/AUTH patterns

**Network exposure:**
- Checks `server.host` or `localServer.host` in JSON for `0.0.0.0` → HIGH
- Runs `ss -tlnp | grep :1234` to detect active listener → CRITICAL if bound to `0.0.0.0`

**Storage:** `PLAINTEXT_JSON`, `PLAINTEXT_ENV`

**Remediation:** `"Bind to 127.0.0.1 instead of 0.0.0.0"`

---

### 18. ML Platforms - Replicate / Together / Groq (`ml-platforms`)

**What it scans:** CLI config files for Replicate, Together, and Groq platforms.

| Platform | Replicate | Together | Groq |
|----------|-----------|----------|------|
| All | `~/.replicate/auth`, `~/.replicate/config.json` | `~/.together/api_key`, `~/.together/config.json` | `~/.groq/api_key`, `~/.groq/config.json` |
| Windows | `%APPDATA%/replicate/config.json` | `%APPDATA%/together/config.json` | `%APPDATA%/groq/config.json` |
| WSL | Both Linux and Windows variants | Both | Both |

**Detection:**
- Plaintext auth/api_key files: entire file content as token
- JSON: recursive walk for keys containing `token`, `key`, `secret`, `api_key`, `apikey`, `access_key` (min length 8)

**Storage:** `PLAINTEXT_FILE`, `PLAINTEXT_JSON`

**Remediation:** `"Use environment variables (REPLICATE_API_TOKEN, TOGETHER_API_KEY, GROQ_API_KEY) instead of config files"`

---

### 19. Network Exposure (`network-exposure`)

**What it scans:** AI service ports listening on non-loopback addresses.

**Applicable:** Linux and WSL only (requires `ss` command).

**Ports monitored:**

| Port | Service |
|------|---------|
| 8888 | Jupyter Notebook/Lab |
| 7860 | Gradio / text-generation-webui |
| 8000 | vLLM |
| 8080 | LocalAI |
| 3000 | Open WebUI |
| 8188 | ComfyUI |

Ports 11434 (Ollama) and 1234 (LM Studio) are handled by their dedicated scanners.

**Detection:** Single `ss -tlnp` call, parses output for `<addr>:<port>` tokens.

**Risk:**
- CRITICAL if bound to `0.0.0.0` or `::`
- HIGH if bound to non-loopback specific address (e.g., LAN IP)
- Localhost bindings (`127.0.0.1`, `::1`) are ignored

**Storage:** `UNKNOWN` (not file-based, no `file_modified`)

**Remediation:** `"Bind <service> to 127.0.0.1 instead of 0.0.0.0, or use an authentication proxy"`

---

### 20. Ollama (`ollama`)

**What it scans:** Ollama environment variables, configs, systemd service, and network exposure.

**Environment variables:**

| Variable | Notes |
|----------|-------|
| `OLLAMA_HOST` | Bind address; `0.0.0.0` → HIGH |
| `OLLAMA_ORIGINS` | CORS origins; `*` → MEDIUM |
| `OLLAMA_MODELS` | Model storage dir |
| `OLLAMA_DEBUG` | Debug flag |
| `OLLAMA_API_KEY` | Auth proxy key |
| `OLLAMA_NUM_PARALLEL` | Concurrency limit |

**Config paths:**

| Platform | Paths |
|----------|-------|
| All | `~/.ollama/` (JSON files) |
| Linux | `/usr/share/ollama/.ollama/`, `/etc/systemd/system/ollama.service`, `/usr/lib/systemd/system/ollama.service` |
| WSL | Also Windows `%USERPROFILE%/.ollama/` |

**Network exposure:** `ss -tlnp | grep :11434` → CRITICAL if bound to `0.0.0.0`.

**Systemd service:** Parses `Environment=` directives for `OLLAMA_HOST=0.0.0.0` and secret keywords.

**Storage:** `ENVIRONMENT_VAR`, `PLAINTEXT_JSON`, `PLAINTEXT_INI` (systemd)

**Remediation:** `"Bind to 127.0.0.1 instead of 0.0.0.0"` / `"Restrict CORS origins"`

---

### 21. OpenAI / Codex CLI (`openai-cli`)

**What it scans:** OpenAI and Codex CLI configuration files.

| Platform | Plaintext key | JSON config | Codex dir |
|----------|--------------|-------------|-----------|
| All | `~/.openai/api_key` | `~/.openai/auth.json` | `~/.codex/*.json` |
| Windows | `%APPDATA%/OpenAI/api_key` | `%APPDATA%/OpenAI/auth.json` | `%APPDATA%/OpenAI/*.json` |
| WSL | Both variants | Both | Both |

**Detection:**
- Plaintext: entire file content as key
- JSON: recursive walk for keys containing `token`, `key`, `secret`, `api_key`, `apikey`, `access_key`, `refresh`

**Storage:** `PLAINTEXT_FILE`, `PLAINTEXT_JSON`

**Remediation:** `"Use OPENAI_API_KEY environment variable instead of plaintext file"`

---

### 22. OpenClaw (`openclaw`)

**What it scans:** OpenClaw auth profiles, credentials, secrets, and gateway configuration.

**Base path:** `~/.openclaw/` (WSL also checks Windows `%USERPROFILE%/.openclaw/`)

**Files scanned:**
- `agents/*/agent/auth-profiles.json` — per-agent OAuth + API keys (glob)
- `credentials/whatsapp/*/creds.json` — WhatsApp account credentials
- `credentials/*.json` — general credentials (oauth, allowlists, etc.)
- `secrets.json` — top-level secrets
- `openclaw.json` — main config (with JS-style `//` comment stripping for JSON5 compat)
- `.env` — environment file
- `credentials/oauth.json` — legacy OAuth
- `openclaw.json` → `gateway.auth` block — gateway tokens

**Secret keys detected:**
- `accessToken`, `access_token`, `refreshToken`, `refresh_token`, `apiKey`, `api_key`, `token`, `auth_token`, `secret`, `password`, `botToken`, `bot_token`, `clientSecret`, `client_secret`

**SecretRef handling:** Values starting with `env:`, `file:`, or `exec:` → INFO finding (external reference, not inline).

**Heuristic:** For other secret-key matches, value must be ≥ 20 chars, ≥ 80% alphanumeric, not a path/URL.

**Storage:** `PLAINTEXT_JSON`, `PLAINTEXT_ENV`

**Recursion:** Max depth 10.

**Remediation:** `"Use SecretRef (env:, file:) instead of inline secrets"`

---

### 23. PowerShell Logs (`powershell`)

**What it scans:** PowerShell history (PSReadLine) and transcripts for AI credentials typed or pasted at the command line.

| Platform | PSReadLine history | Transcripts |
|----------|-------------------|-------------|
| Linux | `~/.local/share/powershell/PSReadLine/ConsoleHost_history.txt`, `~/.config/powershell/PSReadLine/ConsoleHost_history.txt` | `~/Documents/PowerShell_transcript.*.txt`, `~/OneDrive/Documents/PowerShell_transcript.*.txt` |
| macOS | Same as Linux | Same as Linux |
| Windows | `%APPDATA%/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt` | `~/Documents/PowerShell_transcript.*.txt` |
| WSL | Both Linux-side pwsh AND Windows-side PSReadLine | Both Linux-side AND Windows-side |

**Detection (two-pass regex):**

**Pass 1 — Known prefixes (high confidence):**
- Matches any [known credential prefix](#known-prefix-table) followed by 16+ characters from `[A-Za-z0-9_\-./+=]`
- Risk bumped to HIGH (or CRITICAL if file is world-readable)

**Pass 2 — Context patterns (medium confidence):**
- `api_key = "..."`, `$env:TOKEN = "..."`, `-H Authorization: Bearer ...`, `-H x-api-key: ...`, `--api-key ...`
- Secondary heuristic: length ≥ 20, alphanumeric ratio ≥ 75%, not a path/URL

**Deduplication:** Tracks `seen_values` set per file to avoid duplicate findings.

**Location format:** `<path>:<line_number>`

**Storage:** `PLAINTEXT_FILE`

**Remediation:** `"Clear PowerShell history (Remove-Item (Get-PSReadLineOption).HistorySavePath), rotate the exposed credential, and consider Set-PSReadLineOption -HistorySaveStyle SaveNothing for sessions that handle secrets"`

---

### 24. VS Code Extensions (`vscode-extensions`)

**What it scans:** VS Code extension globalStorage for tokens in JSON files.

| Platform | globalStorage path |
|----------|--------------------|
| Linux/WSL | `~/.config/Code/User/globalStorage/` |
| macOS | `~/Library/Application Support/Code/User/globalStorage/` |
| Windows | `%APPDATA%/Code/User/globalStorage/` |

**Excluded extensions** (handled by dedicated scanners):
- `github.copilot`, `github.copilot-chat` (see `github_copilot.py`)
- `saoudrizwan.claude-dev` (see `cline.py`)

**Detection:**
- Recursively walks each extension directory up to depth 3
- Parses all `*.json` files ≤ 1 MB
- Walks JSON trees up to depth 8
- Flags string values where leaf key contains `token`, `key`, `secret`, `password`, `apikey`, or `auth`
- Value must pass heuristic: length ≥ 20, alphanumeric ratio ≥ 80%, not a path/URL, no spaces

**`credential_type` format:** `<extension_id>:<json.path>` (e.g., `rangav.vscode-thunder-client:collections[0].requests[1].headers.Authorization`)

**Storage:** `PLAINTEXT_JSON`

**Remediation:** `"Use VS Code's SecretStorage API or OS keychain for extension credentials"`

---

### 25. Windsurf (`windsurf`)

**What it scans:** Windsurf (Codeium) IDE configuration.

| Platform | Paths |
|----------|-------|
| All | `~/.codeium/windsurf/config.json`, `auth.json`, `credentials.json`, `mcp_config.json` |
| WSL | Also Windows `%USERPROFILE%/.codeium/windsurf/` |

**Detection:**
- Config/auth/credentials JSON: keys `api_key`, `apiKey`, `token`, `auth_token`, `access_token`, `refresh_token`
- MCP config: via `parse_mcp_file`

**Storage:** `PLAINTEXT_JSON`

**Remediation:** `"Restrict file permissions: chmod 600 <path>"`

---

## Common Patterns

### Registration pattern

Every scanner follows this pattern:

```python
from aihound.scanners import register
from aihound.core.scanner import BaseScanner, CredentialFinding, ScanResult, StorageType

@register
class MyScanner(BaseScanner):
    def name(self) -> str:
        return "My Tool"

    def slug(self) -> str:
        return "my-tool"

    def is_applicable(self) -> bool:
        return True  # or platform check

    def scan(self, show_secrets: bool = False) -> ScanResult:
        result = ScanResult(scanner_name=self.name(), platform=detect_platform().value)
        # ... scanning logic ...
        return result
```

### Finding construction pattern

```python
finding = CredentialFinding(
    tool_name=self.name(),
    credential_type="api_key",
    storage_type=StorageType.PLAINTEXT_JSON,
    location=str(path),
    exists=True,
    risk_level=assess_risk(StorageType.PLAINTEXT_JSON, path),
    value_preview=mask_value(value, show_full=show_secrets),
    raw_value=value if show_secrets else None,
    file_permissions=get_file_permissions(path),
    file_owner=get_file_owner(path),
    file_modified=get_file_mtime(path),
    remediation="Restrict file permissions: chmod 600 " + str(path),
    notes=[f"File last modified: {describe_staleness(mtime)}"],
)
result.findings.append(finding)
```

### Error handling

Scanners should never raise — all errors go into `ScanResult.errors`:

```python
try:
    data = json.loads(path.read_text())
except (OSError, json.JSONDecodeError) as e:
    result.errors.append(f"Failed to parse {path}: {e}")
    return
```

`BaseScanner.run()` provides a final safety net with `try/except` around the entire scan.

### Inline-secret heuristic

Used across many scanners to distinguish real secrets from URLs, paths, and other non-secret strings:

```python
def _looks_like_secret(value: str) -> bool:
    if len(value) < 20:
        return False
    if value.startswith(("/", "\\", "http://", "https://", "C:", "c:")):
        return False
    alnum = sum(1 for c in value if c.isalnum())
    return alnum / len(value) >= 0.80
```

### Recursive JSON descent

Used for nested credential hunting:

```python
def _walk(obj, path_parts, depth=0):
    if depth > MAX_DEPTH:
        return
    if isinstance(obj, dict):
        for key, val in obj.items():
            _walk(val, path_parts + [key], depth + 1)
    elif isinstance(obj, list):
        for i, val in enumerate(obj):
            _walk(val, path_parts + [f"[{i}]"], depth + 1)
    elif isinstance(obj, str):
        leaf_key = path_parts[-1].lower() if path_parts else ""
        if any(pat in leaf_key for pat in SECRET_KEYS):
            # found a candidate
            ...
```

### WSL dual-path pattern

```python
paths = [home / "somedir" / "config.json"]
if plat == Platform.WSL:
    win_home = get_wsl_windows_home()
    if win_home:
        paths.append(win_home / "somedir" / "config.json")
```

### Network exposure check pattern

```python
try:
    result = subprocess.run(
        ["ss", "-tlnp"], capture_output=True, text=True, timeout=5
    )
    for line in result.stdout.splitlines():
        if f":{port}" in line and "0.0.0.0" in line:
            # flag as CRITICAL
            ...
except (FileNotFoundError, subprocess.TimeoutExpired):
    pass  # ss not available or timed out
```

---

## Appendix: Versioning and Change Log

This document describes AIHound at the v0.1.0 codebase. As new scanners, features, and output formats are added, append new sections here rather than creating separate docs.

### Recent additions (post-v0.1.0)

- **v3 features** — Added 10 new scanners (`aider`, `huggingface`, `openai_cli`, `git_credentials`, `ml_platforms`, `network_exposure`, `docker`, `jupyter`, `vscode_extensions`, `browser_sessions`), plus the `PLAINTEXT_FILE` storage type, `file_modified` and `remediation` fields on `CredentialFinding`, staleness tracking, and remediation guidance across all output formats.
- **PowerShell scanner** — Added `powershell` scanner for PSReadLine history and transcripts with two-pass regex detection (known prefixes + context patterns).

### Pending / Future work

- **MCP server mode (feature 18)** — Run AIHound itself as an MCP server so AI assistants can query credential status directly. Tracked in memory, to be implemented separately.
- **Go port feature parity** — Port the v3 features and PowerShell scanner to the Go version under `Go/`.
