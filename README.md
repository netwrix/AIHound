<div align="center">

# AIHound

### AI Credential & Secrets Scanner

<p>
  <img src="aihound.png" alt="AIHound" width="500">
</p>

[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](#prerequisites)
[![Version](https://img.shields.io/badge/version-3.2.2-green?style=flat-square)](#)
[![Scanners](https://img.shields.io/badge/AI_tool_scanners-29-brightgreen?style=flat-square)](#step-5-scan-specific-tools)
[![Platforms](https://img.shields.io/badge/platforms-Windows%20%7C%20macOS%20%7C%20Linux%20%7C%20WSL-blueviolet?style=flat-square)](#wsl-users)
[![Outputs](https://img.shields.io/badge/outputs-HTML%20%7C%20JSON%20%7C%20BloodHound-orange?style=flat-square)](#step-4-generate-reports)
[![BloodHound](https://img.shields.io/badge/BloodHound_CE-compatible-red?style=flat-square)](#bloodhound-attack-path-graph)
[![MCP Server](https://img.shields.io/badge/MCP_Server-enabled-9cf?style=flat-square)](docs/Full-Documentation.md)
<!-- [![GitHub stars](https://img.shields.io/github/stars/netwrix/AIHound?style=flat-square)](https://github.com/netwrix/AIHound/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/netwrix/AIHound?style=flat-square)](https://github.com/netwrix/AIHound/network/members)
[![Last Commit](https://img.shields.io/github/last-commit/netwrix/AIHound?style=flat-square)](https://github.com/netwrix/AIHound/commits/main) -->
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](https://github.com/netwrix/AIHound/pulls)

**29 AI tool scanners · 4 platforms · BloodHound attack path export · MCP server mode · Watch mode**

[Get Started](#step-1-get-aihound) · [Reports](#step-4-generate-reports) · [BloodHound](#bloodhound-attack-path-graph) · [Scan Tools](#step-5-scan-specific-tools) · [Documentation](https://github.com/netwrix/AIHound/tree/main/docs)

</div>

---

AIHound is an AI Assistant credential and secrets scanner that detects exposed API keys, OAuth tokens, MCP server secrets, and session credentials across 29 AI tools on Windows, macOS, Linux, and WSL. Beyond one-shot scanning with terminal, it offers a watch mode for continuous monitoring that alerts on new, changed, or escalated credentials in real time.

AIHound includes an MCP server mode that lets AI assistants like Claude Code scan for and remediate credential issues programmatically.

AIHound can export to **SpectorOps' BloodHound**. Scan results export as OpenGraph JSON that can be ingested into BloodHound to visualize attack paths, showing compromised credential chains through MCP servers, AI services, and datastores. I've included 29 pre-built Cypher queries for blast radius analysis, same-secret detection, and lateral movement mapping.

> This is a security research tool. Credentials are **redacted by default** so output is safe to share in reports and screenshots.

Get scanning in under 2 minutes.

## **PyInstaller Precompiled .exe version can be found [Here](https://github.com/netwrix/AIHound/tree/main/Other%20Versions/pyinstaller/dist)**
## **Go Precompiled .exe version can be found [Here](https://github.com/netwrix/AIHound/tree/main/Other%20Versions/Go/dist)**

AIHound can be run four ways: from Python source, using the Go runtime. as a compiled Go binary, or as a standalone Windows executable.

### Full Documentation located [Here](https://github.com/netwrix/AIHound/tree/main/docs)

## Prerequisites

- Python 3.10 or higher
- That's it. No pip install required for basic scanning.

## Step 1: Get AIHound

```bash
git clone https://github.com/netwrix/AIHound.git
cd AIHound
```

## Step 2: Run Your First Scan

```bash
python3 -m aihound
```

You'll see output like this:

```
╔══════════════════════════════════════════════════════════════╗
║          AIHound - AI Credential & Secrets Scanner           ║
╚══════════════════════════════════════════════════════════════╝

Platform: wsl
WSL detected - scanning both Linux and Windows credential paths

Tool             Credential Type        Storage      Location                            Risk
-------------------------------------------------------------------------------------------------
Claude Code CLI  oauth_access_token     plaintext... ~/.claude/.credentials.json          CRITICAL
                   Value: sk-ant-oat01-Z...eAAA
Claude Code CLI  oauth_refresh_token    plaintext... ~/.claude/.credentials.json          HIGH
                   Value: sk-ant-ort01-r...ygAA

Summary: 2 findings | 1 CRITICAL | 1 HIGH
```

All secret values are automatically redacted. The tool is read-only and doesn't touch your credentials.

## Step 3: Get More Detail

Add `-v` for verbose output — shows file permissions (with human-readable descriptions), ownership, expiry times, and notes:

```bash
python3 -m aihound -v
```

```
Claude Code CLI  oauth_access_token     plaintext... ~/.claude/.credentials.json          CRITICAL
                   Value: sk-ant-oat01-Z...eAAA
                   Note: Expires: 2026-03-09 23:30 UTC
                   Perms: 0777 (world-writable, world-readable, DANGEROUS) Owner: ull
```

## Step 4: Generate Reports

### HTML Report

Creates a self-contained HTML file with the AIHound banner, dark theme, and color-coded risk table:

```bash
python3 -m aihound --html-file report.html
```

Open `report.html` in your browser. Great for sharing with your team or including in assessments.

### JSON Report

For automation, pipelines, or feeding into other tools:

```bash
# Write to file
python3 -m aihound --json-file report.json

# Pipe to stdout
python3 -m aihound --json | jq '.summary'
```

### BloodHound Attack Path Graph

Export to [BloodHound CE](https://github.com/SpecterOps/BloodHound) for interactive attack path visualization — see how credentials chain together across tools, services, and data stores:

```bash
python3 -m aihound --bloodhound aihound-bloodhound.json
```

Then upload `aihound-bloodhound.json` to BloodHound CE (v9.x) via **Quick Upload** or **Data Collection > File Ingest**.

**First time?** Register custom node types and saved Cypher queries (once per BloodHound instance):
>register_ai_nodes.py script located in docs folder.

```bash
python3 docs/register_ai_nodes.py -s http://<bloodhound IP>:8080 -u admin -p <password>
```

This registers 14 custom node kinds with icons and imports 29 saved Cypher queries into BloodHound's Saved Queries panel. Use `--reset` to re-register, `--unregister` to remove everything, or `--no-queries` to skip query import.

Example Cypher queries (also available in Saved Queries after registration):

```cypher
// Show the full credential graph
MATCH path = (a:AIHound)-[r]->(b:AIHound) RETURN path

// Blast radius from critical credentials
MATCH path = (c:AICredential)-[*1..4]->(target)
WHERE c.risk_level = "critical"
RETURN path

// MCP server attack chain: tool -> server -> credential -> service
MATCH path = (t:AITool)-[:UsesMCPServer]->(m:MCPServer)-[:RequiresCredential]->(c:AICredential)-[:Authenticates]->(s:AIService)
RETURN path
```

See `BLOODHOUND_GUIDE.md` located [Here](https://github.com/netwrix/AIHound/tree/main/docs) for the full walkthrough and `cypher_queries.cy` for all 29 pre-built queries.

<img width="1768" height="937" alt="Screenshot 2026-05-12 135945" src="https://github.com/user-attachments/assets/72d00b53-662b-40a4-be8d-cd95be86eee7" />

### All at once

```bash
python3 -m aihound -v --html-file report.html --json-file report.json --bloodhound bloodhound.json
```

## Step 5: Scan Specific Tools

List what's available:

```bash
python3 -m aihound --list-tools
```

```
Available scanners:
  amazon-q             Amazon Q / AWS                 Applicable: yes
  chatgpt              ChatGPT Desktop                Applicable: yes
  claude-code          Claude Code CLI                Applicable: yes
  claude-desktop       Claude Desktop                 Applicable: yes
  cline                Cline (VS Code)                Applicable: yes
  continue-dev         Continue.dev                   Applicable: yes
  cursor               Cursor IDE                     Applicable: yes
  envvars              Environment Variables          Applicable: yes
  gemini               Gemini CLI / GCloud            Applicable: yes
  github-copilot       GitHub Copilot                 Applicable: yes
  windsurf             Windsurf                       Applicable: yes
```

Scan only specific tools by slug:

```bash
python3 -m aihound --tools claude-code claude-desktop envvars
```

## What Does Each Risk Level Mean?

| Level | What It Means | What To Do |
|---|---|---|
| **CRITICAL** | Plaintext secret in a world-readable file | Fix file permissions immediately (`chmod 600`) |
| **HIGH** | Plaintext secret, only owner can read | Acceptable for some tools, but consider using OS keychain |
| **MEDIUM** | OS credential store or environment variable | Standard practice, but be aware of the exposure |
| **LOW** | Encrypted storage | Generally acceptable |
| **INFO** | Metadata, not an actual secret | No action needed |

## WSL Users

If you're running on WSL, AIHound automatically detects it and scans **both**:
- Linux-native paths (`~/.claude/`, `~/.aws/`, etc.)
- Windows paths via `/mnt/c/Users/<you>/AppData/...`

This often reveals credentials in Windows app data that have overly permissive permissions (e.g., `0777`) when viewed from WSL.

## Common Findings & What They Mean

### "oauth_access_token" / "oauth_refresh_token" — Claude Code
Claude Code stores OAuth tokens in `~/.claude/.credentials.json`. The access token is short-lived (hours), but the **refresh token is long-lived** and can be used to generate new access tokens.

### "mcp_env:ADO_MCP_AUTH_TOKEN" — MCP Servers
MCP server configurations often embed auth tokens directly in JSON config files. If you see inline secrets here, consider using environment variable references (`${VAR_NAME}`) instead.

### "api_key (anthropic)" — Continue.dev
Continue.dev stores API keys in plaintext in `~/.continue/config.json`. Use the `${ENV_VAR}` syntax in the config to avoid this.

### AWS credentials
`~/.aws/credentials` contains long-lived access keys. Consider using SSO/IAM Identity Center instead of static keys.

## Next Steps

- Review findings and fix any CRITICAL/HIGH issues
- Generate an HTML report for your team: `python3 -m aihound --html-file report.html`
- Export to BloodHound for attack path visualization: `python3 -m aihound --bloodhound bloodhound.json`
- See `BLOODHOUND_GUIDE.md` for the full BloodHound walkthrough
- Check the full Documentation [Here](https://github.com/netwrix/AIHound/tree/main/docs) for watch mode, MCP server mode, and advanced usage
