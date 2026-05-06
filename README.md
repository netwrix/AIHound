# AIHound Quick Start Guide

**AI Credential & Secrets Scanner**

<p align="center">
  <img src="aihound.png" alt="AIHound" width="500">
</p>

AIHound is an AI Assistant credential and secrets scanner that detects exposed API keys, OAuth tokens, MCP server secrets, and session credentials across 29 AI tools on Windows, macOS, Linux, and WSL. Beyond one-shot scanning with terminal, it offers a watch mode for continuous monitoring that alerts on new, changed, or escalated credentials in real time.

  AIHound includes an MCP server mode that lets AI assistants like Claude Code scan for and remediate credential issues programmatically. 
  
  AIHound can export to **SpectorOps' BloodHound**. Scan results export as OpenGraph JSON that can be ingested into BloodHound to visualize attack paths, showing compromised credential chains through MCP servers, AI services, and datastores. I've included 29 pre-built Cypher queries for blast radius analysis, same-secret detection, and lateral movement mapping. 


>This is a security research tool. Credentials are **redacted by default** so output is safe to share in reports and screenshots.

Get scanning in under 2 minutes.

### Full Documentation located [Here](https://github.com/netwrix/AIHound/tree/main/docs)

## Prerequisites

- Python 3.10 or higher
- That's it. No pip install required for basic scanning.

## Step 1: Get AIHound

```bash
git clone https://github.com/netwrix/aihound.git
cd aihound
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

### BloodHound Attack Path Graph (v3.2.0)

Export to [BloodHound CE](https://github.com/SpecterOps/BloodHound) for interactive attack path visualization — see how credentials chain together across tools, services, and data stores:

```bash
python3 -m aihound --bloodhound aihound-bloodhound.json
```

Then upload `aihound-bloodhound.json` to BloodHound CE (v8.0+) via **Data Collection > File Ingest**.

**First time?** Register custom node types (once per BloodHound instance):
>register_ai_nodes.py script located in docs folder. 

```bash
python3 register_ai_nodes.py -s http://<bloodhound IP>:8080 -u admin -p <password>
```

Example Cypher queries to run in BloodHound:

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
