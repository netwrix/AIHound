# MCP Client Configs

Drop-in configurations for adding AIHound to popular MCP clients.

## Prerequisites

Install the `mcp` SDK alongside AIHound:

```bash
pip install aihound[mcp]
```

This makes `aihound --mcp` work as a standalone command.

---

## Claude Desktop

**File:** `claude-desktop.json`

**Where it goes:**
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

If the file already exists, **merge** the `mcpServers` block — don't overwrite the file. Example merged config:

```json
{
  "preferences": { "...your existing prefs..." },
  "mcpServers": {
    "aihound": {
      "command": "aihound",
      "args": ["--mcp"]
    }
  }
}
```

Restart Claude Desktop completely (right-click tray → Quit, then reopen).

---

## Claude Code

**File:** `claude-code.json` — drop in the **root of any project** as `.mcp.json` to enable for that project.

```bash
cp examples/mcp-configs/claude-code.json .mcp.json
```

When anyone opens that project in Claude Code, they'll be prompted to enable the AIHound MCP server.

**Alternative — add globally for yourself:**
```bash
claude mcp add aihound -- aihound --mcp
```

This adds AIHound for your user across all projects without needing the file.

---

## Cursor

**File:** `cursor.json`

**Where it goes:**
- Per-user: `~/.cursor/mcp.json`
- Per-project: `.cursor/mcp.json` in the project root

---

## Windsurf

**File:** `windsurf.json`

**Where it goes:** `~/.codeium/windsurf/mcp_config.json`

Restart Windsurf after editing.

---

## Variants

The example configs assume `aihound` is on your `PATH` (true after `pip install aihound[mcp]`). If your setup differs, swap out `command` and `args`:

### Running from source (no pip install)

```json
{
  "command": "python",
  "args": ["-m", "aihound", "--mcp"],
  "env": {
    "PYTHONPATH": "/path/to/aicreds"
  }
}
```

### Specific Python interpreter

```json
{
  "command": "/usr/bin/python3.12",
  "args": ["-m", "aihound", "--mcp"]
}
```

### Windows with full path

```json
{
  "command": "C:\\Users\\YOU\\AppData\\Local\\Microsoft\\WindowsApps\\python.exe",
  "args": ["-m", "aihound", "--mcp"],
  "env": {
    "PYTHONPATH": "C:\\path\\to\\aicreds"
  }
}
```

### PyInstaller .exe (Windows, no Python required)

As of v3.0.0, the shipped `pyinstaller/dist/aihound.exe` bundles the `mcp` SDK — it works as an MCP server out of the box, no Python install needed:

```json
{
  "command": "C:\\path\\to\\aihound.exe",
  "args": ["--mcp"]
}
```

This is the friendliest path for Windows users who don't have Python and don't want to install it.

If you're rebuilding the .exe yourself, make sure `pip install mcp` runs in the build Python first so PyInstaller can find the SDK to bundle. The default `pyinstaller/aihound.spec` already lists `aihound.mcp_server` in `hidden_imports`.

### Go binary

```json
{
  "command": "C:\\path\\to\\aihound.exe",
  "args": ["--mcp"]
}
```

The Go binary (`Other Versions/Go/`, built with `go build ./cmd/aihound`) also exposes `--mcp` as a stdio server. Same 4 tools, same 2 resources, same JSON shape as the Python server. Useful if you prefer a single static binary with no Python runtime at all (~18 MB, cross-compiles to any OS).

---

## Verifying it works

After registering and restarting your client, ask the AI:

> List all the AIHound scanners and tell me what each one checks for.

If the integration works, the AI will call `aihound_list_scanners` and report back with all 25 scanners. You should see a tool-call indicator in the chat UI.

If nothing happens:
- Check the client's MCP log (Claude Desktop: `%APPDATA%\Claude\logs\mcp.log`)
- Verify `aihound --mcp` works standalone — it should hang waiting for stdin (Ctrl+C to exit)
- Look for `[error] [aihound]` lines in the log

## Available tools

Once connected, the AI can call:

| Tool | Use |
|------|-----|
| `aihound_scan` | Run all (or some) scanners, return findings with masked previews and remediation hints |
| `aihound_list_scanners` | Enumerate all 25 scanners and platform applicability |
| `aihound_get_remediation` | Look up the structured fix for a specific finding by `finding_id` |
| `aihound_check` | Run a single scanner (bypass cache) |

And read these resources:

| Resource | Contents |
|----------|----------|
| `aihound://findings/latest` | Most recent cached scan |
| `aihound://platform` | Detected OS + WSL status + version |

## Security note

AIHound's MCP server **never** sends raw credential values over the wire — only masked previews and structured remediation hints. The AI assistant can advise and (using its own filesystem tools) execute fixes, but it cannot exfiltrate the actual secrets.
