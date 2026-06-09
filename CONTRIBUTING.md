# Contributing to AIHound

Thanks for your interest in contributing to AIHound! Whether you're adding a new AI tool scanner, fixing a bug, or improving docs, this guide will get you started.

## Quick Start

```bash
git clone https://github.com/netwrix/AIHound.git
cd AIHound
python3 -m aihound            # verify it runs
python3 -m aihound --list-tools  # see all scanners
```

No pip install is needed for basic development. For optional features:

```bash
pip install rich       # colored terminal output
pip install mcp        # MCP server mode
```

## Adding a New Scanner

This is the most common contribution. AIHound uses a plugin system — drop a file in `aihound/scanners/` and it's automatically discovered.

### 1. Create Your Scanner File

Create `aihound/scanners/your_tool.py`. Use this template:

```python
from __future__ import annotations
from pathlib import Path

from aihound.core.scanner import (
    BaseScanner,
    CredentialFinding,
    RiskLevel,
    ScanResult,
    StorageType,
)
from aihound.core.platform import detect_platform, get_home
from aihound.core.permissions import get_file_permissions, get_file_owner, assess_risk
from aihound.core.redactor import mask_value, identify_credential_type
from aihound.scanners import register


@register
class YourToolScanner(BaseScanner):
    def name(self) -> str:
        return "Your Tool Name"

    def slug(self) -> str:
        return "your-tool"

    def is_applicable(self) -> bool:
        """Return True if this tool's config files exist on the current system."""
        return self._config_path().exists()

    def scan(self, show_secrets: bool = False) -> ScanResult:
        findings = []
        errors = []

        config_path = self._config_path()
        if not config_path.exists():
            return ScanResult(findings=findings, errors=errors,
                              scanner_name=self.name(), platform=detect_platform())

        # Parse the config, find credentials, create findings:
        # findings.append(CredentialFinding(
        #     tool_name=self.name(),
        #     credential_type="api_key",
        #     storage_type=StorageType.PLAINTEXT_JSON,
        #     location=str(config_path),
        #     risk_level=RiskLevel.HIGH,
        #     value=mask_value(raw_value) if not show_secrets else raw_value,
        # ))

        return ScanResult(findings=findings, errors=errors,
                          scanner_name=self.name(), platform=detect_platform())

    def _config_path(self) -> Path:
        return get_home() / ".your-tool" / "config.json"
```

### 2. Reference Existing Scanners

- **Simple example:** `aihound/scanners/envvars.py` — scans environment variables
- **Complex example:** `aihound/scanners/claude_code.py` — multiple credential types, expiry parsing, MCP config scanning
- **MCP config scanning:** Any scanner using `parse_mcp_file()` from `aihound.core.mcp`

### 3. Test Your Scanner

```bash
# Run only your scanner
python3 -m aihound --tools your-tool

# Verbose output to verify findings
python3 -m aihound --tools your-tool -v

# Verify it shows up in the list
python3 -m aihound --list-tools
```

### Key Concepts

| Concept | Description |
|---------|-------------|
| `@register` | Decorator that auto-registers your scanner class |
| `BaseScanner` | Abstract base class — implement `name()`, `slug()`, and `scan()` |
| `is_applicable()` | Return `False` if the tool isn't installed (skips the scanner gracefully) |
| `RiskLevel` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `StorageType` | `PLAINTEXT_JSON`, `PLAINTEXT_YAML`, `PLAINTEXT_ENV`, `KEYCHAIN`, `CREDENTIAL_MANAGER`, `ENVIRONMENT_VAR`, etc. |
| `mask_value()` | Redacts secrets by default — always use this unless `show_secrets` is True |

## Other Ways to Contribute

### Bug Reports

Open an issue with:
- What you ran (command + flags)
- What you expected
- What actually happened
- Your platform (Windows, macOS, Linux, WSL)

### Improving Existing Scanners

- Add detection for new credential types in existing tools
- Improve `is_applicable()` checks for cross-platform support
- Add or refine remediation hints

### Documentation

- Improve the docs in `docs/`
- Add example configs to `docs/Example MCP Configs/`
- Improve inline code comments

### Output Formats

- Output formatters live in `aihound/output/`
- If you want to add a new export format (CSV, SARIF, etc.), look at `json_export.py` as a starting point

## Project Structure

```
aihound/
  cli.py                 # CLI argument parsing and main entry point
  mcp_server.py          # MCP server mode
  watch.py               # Watch mode (continuous monitoring)
  notifications.py       # Desktop notifications for watch mode
  remediation.py         # Remediation hint generators
  core/
    scanner.py           # BaseScanner, CredentialFinding, data models
    platform.py          # Platform detection, path helpers
    permissions.py       # File permission checks, risk assessment
    redactor.py          # Secret masking
    mcp.py               # MCP config file parser
  scanners/              # All scanner plugins (auto-discovered)
  output/                # Output formatters (table, HTML, JSON, BloodHound)
  utils/                 # OS credential store helpers (keychain, credman, vscdb)
docs/                    # Documentation, Cypher queries, BloodHound guide
Other Versions/          # Go and PyInstaller builds
```

## Guidelines

- **Redact by default.** Never output raw secrets unless `show_secrets=True`.
- **Read-only.** AIHound never modifies credential files. Scanners are strictly read-only.
- **Cross-platform.** Use `aihound.core.platform` helpers for paths. Test on your platform and note which platforms your scanner supports.
- **Fail gracefully.** If a file doesn't exist or can't be parsed, add to `errors` and continue — don't crash the scan.
- **Keep it simple.** A scanner should do one thing: find credentials for a specific tool.

## Submitting a PR

1. Fork the repo and create a branch (`git checkout -b add-scanner-newtool`)
2. Make your changes
3. Test locally with `python3 -m aihound`
4. Open a PR with a brief description of what you added/changed

That's it. No complex CI pipeline to worry about.
