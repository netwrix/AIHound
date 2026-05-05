# AIHound

**A security tool that finds AI credentials and secrets sitting in plaintext on developer machines — and helps fix them.**

---

## The Problem

Modern developers use 10+ AI tools. Each one needs an API key, an OAuth token, or session credentials.

Most of those credentials end up in plaintext files like `~/.claude/.credentials.json`, `~/.docker/config.json`, `~/.aws/credentials`, browser localStorage, or even pasted into PowerShell history. A compromised laptop, a stolen backup, or a malicious local process is all it takes to exfiltrate them.

Until now, no single tool covered the full landscape — every AI assistant, every CLI, every local AI server, every config file, every shell history. **AIHound does.**

---

## What AIHound Does (in one paragraph)

AIHound scans a workstation for **29 different categories of AI credentials and secrets** — across files, environment variables, OS keychains, browser storage, shell history, network listeners, and Docker registries — and produces a risk-rated report with **actionable remediation guidance** on every finding. It's read-only, redacts secrets by default, and runs on Windows, macOS, Linux, and WSL.

---

## Coverage at a Glance

### 29 scanners, organized by category:

#### AI Assistants & Desktop Apps
- Claude Code CLI
- Claude Desktop
- ChatGPT Desktop

#### AI Coding Assistants & IDEs
- GitHub Copilot
- Cursor IDE
- Continue.dev
- Cline (VS Code extension)
- Windsurf
- Aider
- VS Code Extensions (AWS Toolkit, Azure Tools, GitLens, Thunder Client, etc.)

#### AI CLIs & Platforms
- OpenAI / Codex CLI
- Hugging Face CLI
- Gemini CLI / Google Cloud
- Amazon Q / AWS
- Replicate / Together / Groq
- OpenClaw

#### Local AI Servers (with network exposure detection)
- Ollama (port 11434)
- LM Studio (port 1234)
- Jupyter (port 8888)
- AI Network Exposure scanner — Gradio (7860), vLLM (8000), LocalAI (8080), Open WebUI (3000), ComfyUI (8188)

#### Shell History & Configuration
- **Shell History** — bash, zsh, fish history files scanned with two-pass regex (known-prefix + context-based)
- **PowerShell Logs** — API keys typed or pasted into PSReadLine history and transcript files
- **Shell RC Files** — `.bashrc`, `.zshrc`, fish `config.fish`, PowerShell profiles, `.env` files for hardcoded `export VAR=secret`
- **Persistent Environment** — `/etc/environment`, `/etc/profile.d/`, `~/.pam_environment`, systemd `environment.d`, macOS LaunchAgents, Windows registry (`HKCU\Environment`, `HKLM\...\Environment`)

#### Active Sessions & Runtime
- **Claude Sessions** — running `claude` processes (local + SSH-originated), `~/.claude/sessions/` files, live OAuth tokens, tmux/screen sessions hosting Claude, MCP servers exposed on `0.0.0.0`

#### Developer & Operational Surfaces
- **Docker** — base64 auth blobs in `~/.docker/config.json`
- **Git Credentials** — plaintext `~/.git-credentials`, embedded tokens in `.gitconfig`
- **Browser Sessions** — Firefox localStorage for AI domains (claude.ai, chatgpt.com, gemini, perplexity, copilot, huggingface)
- **Environment Variables** — 35+ AI-related env vars (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GITHUB_TOKEN`, `AWS_ACCESS_KEY_ID`, etc.)

---

## Types of Secrets Detected

AIHound recognizes credentials by their known prefixes — meaning even a token pasted into a random log file gets identified correctly:

| Prefix | Provider |
|--------|----------|
| `sk-ant-`, `sk-ant-oat`, `sk-ant-ort` | Anthropic (API keys, OAuth access, OAuth refresh) |
| `sk-`, `sk-proj-` | OpenAI / Generic |
| `ghp_`, `gho_`, `ghu_`, `ghs_`, `github_pat_` | GitHub PATs and OAuth tokens |
| `xoxb-`, `xoxp-`, `xoxa-` | Slack (Bot, User, App tokens) |
| `AKIA` | AWS Access Keys |
| `AIza` | Google API Keys |
| `ya29.` | Google OAuth Access Tokens |
| `hf_` | Hugging Face tokens |

Plus **structural detection** in JSON, YAML, INI, `.env` files, MCP server configs, base64-encoded Docker auth blobs, and SQLite databases.

---

## What Makes a Finding Critical

Every finding gets a risk level based on **how the credential is stored AND who can read it:**

| Level | Means |
|-------|-------|
| **CRITICAL** | Plaintext + world-readable file, OR an unauthenticated AI server listening on `0.0.0.0`, OR an empty Jupyter token, OR a Claude MCP server exposed on the network |
| **HIGH** | Plaintext credential file with user-only permissions, OR a known API key prefix found in shell history, OR an SSH-originated Claude session, OR a live OAuth token with an active Claude process |
| **MEDIUM** | OS credential store (Keychain, Windows Credential Manager), env var, or encrypted DB |
| **LOW** | Encrypted storage |
| **INFO** | Metadata only — no secret value exposed |

---

## Three Ways to Run It

| Distribution | Best For | Size | Dependencies |
|--------------|----------|------|--------------|
| **PyInstaller `.exe`** | Distributing to teammates who don't want to install anything | 21 MB | None — standalone Windows binary |
| **Go binary** | Embedded use, CI/CD pipelines, fleet deployment | 18 MB | None — pure static binary, cross-compiles to any OS |
| **Python source** | Active development, customization, easy updates | N/A | Python 3.10+ |

All three produce identical findings.

---

## Three Operating Systems

| Platform | Status |
|----------|--------|
| **Windows** | Full support — Credential Manager queries, PowerShell history, registry-aware paths |
| **macOS** | Full support — Keychain queries, Library/Application Support paths |
| **Linux** | Full support — XDG paths, systemd service file scanning, network port detection |
| **WSL** | **Bonus: dual-scan** — checks both Linux paths AND Windows paths via `/mnt/c/`, giving you the full picture from one terminal |

---

## Cool Feature #1: Watch Mode

AIHound can run **continuously** and alert you the moment a credential's situation changes — a new credential appears, a file's permissions get loosened, or a local AI server starts listening on `0.0.0.0`.

Output goes to terminal, NDJSON log files, and OS-native desktop notifications (with configurable risk thresholds).

### Use Case: Developer Hygiene Sentinel

> A developer installs a new AI tool — say, Aider — and runs `aider` for the first time. The tool silently writes `~/.aider.conf.yml` with their OpenAI API key in plaintext at `0644` permissions.

Without AIHound: the credential sits there for months, exposed.

With AIHound running in watch mode:

```
[10:45:03] NEW       CRITICAL  Aider     openai-api-key   ~/.aider.conf.yml
            └─ Fix: Use environment variables (OPENAI_API_KEY) instead of config file
```

A desktop notification fires within 30 seconds. The developer fixes it before lunch.

---

## Cool Feature #2: MCP Server Mode

AIHound can run as a **Model Context Protocol server**, letting AI assistants (Claude Desktop, Claude Code, Cursor, Windsurf) directly call its scanners as tools — and even execute fixes themselves using their own filesystem access.

### Use Case: Conversational Credential Triage and Repair

> Security analyst opens Claude Desktop and types:
>
> *"Scan my machine for exposed AI credentials and fix anything CRITICAL."*

Claude:
1. Calls `aihound_scan(min_risk="critical")` → gets back 4 findings, each with a structured `remediation_hint` like `{"action": "chmod", "args": ["600", "/home/user/.claude/.credentials.json"]}`
2. Reads each hint and runs the appropriate `chmod` / config edit / env-var migration using its filesystem tools
3. Calls `aihound_scan(force=True)` to re-verify
4. Reports back: *"Fixed 4 CRITICAL findings. All credential files now `0600` (owner-only). No CRITICAL findings remain."*

**Critical security guarantee:** AIHound never sends raw credential values over MCP. The AI sees masked previews and structured fix hints — it can advise and execute, but it cannot exfiltrate the actual secrets.

---

## Other Capabilities Worth Highlighting

- **Remediation guidance on every finding** — both human-readable strings AND machine-readable structured hints (chmod, migrate-to-env-var, change config field, run command, use credential helper, rotate credential)
- **File staleness detection** — knows when a credential was last touched ("modified 281 days ago" suggests an abandoned key worth rotating)
- **Network exposure scanner** — detects when local AI services are bound to `0.0.0.0` instead of `127.0.0.1`
- **Three output formats** — colored terminal table, JSON, self-contained HTML report
- **Plugin architecture** — adding a new scanner is one new file, zero changes elsewhere
- **85 unit tests** — covering credential masking, MCP parsing, watch mode diff engine, hint serialization, scanner registry

---

## Safety & Ethics

AIHound is built for **authorized security research, penetration testing, and defensive assessments**. Specifically:

- **Read-only** — never modifies, exfiltrates, or transmits credentials
- **Redacted by default** — credential values are masked unless `--show-secrets` is used (which requires interactive `YES` confirmation on a TTY)
- **JSON output never includes raw values** — even with `--show-secrets`
- **MCP responses never include raw values** — non-negotiable, enforced at the serialization boundary

The banner displayed at every scan reminds users: *"For authorized use only. Use on systems you own or have permission to test."*

---

## Why This Matters to the Business

**Visibility.** You can't fix what you can't see. AIHound gives security teams (and developers) a single, comprehensive view of every AI credential sitting on a workstation.

**Friction-free remediation.** Every finding ships with both human guidance and AI-executable fix actions. Combined with MCP mode, this means a developer can resolve all CRITICAL findings via a single conversation with Claude — no security team escalation needed.

**Defense in depth.** Watch mode catches new exposures the moment they appear, before a credential gets stolen, committed to git, or backed up to a less secure location.

**Operational fit.** Three deployment options cover every scenario — drop the `.exe` on a Windows machine for a one-off audit, ship the Go binary in a CI pipeline, or run from Python source for development.

---

## Status

**v3.0.0** — Production-ready. All features at parity across Python, Go, and PyInstaller. 29 scanners. 128+ passing tests. Cross-platform (Windows / macOS / Linux / WSL).

Built by Darryl Baker (DFIRDeferred), Netwrix.
