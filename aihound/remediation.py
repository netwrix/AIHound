"""Structured remediation hints.

Every CredentialFinding can carry a machine-readable `remediation_hint` dict
alongside its human-readable `remediation` string. AI assistants (via MCP) read
the structured hint and execute fixes using their own filesystem tools.

Hint schema: a freeform dict keyed by an `action` string. Known actions:

| action                  | required fields                           | description |
|-------------------------|-------------------------------------------|-------------|
| chmod                   | args: [mode, path]                        | Restrict file permissions |
| migrate_to_env          | env_vars: [str], source: path             | Move secret from file to env var |
| change_config_value     | target: str, new_value, source: path      | Update a config field |
| run_command             | commands: [str], shell: str               | Execute specific shell commands |
| use_credential_helper   | tool: str, helper_options: [str]          | Switch to OS credential helper |
| rotate_credential       | provider: str, description: str           | External rotation action |
| manual                  | description: str                          | General fallback |

Scanners use these helpers instead of constructing dicts inline. Keeps scanner
code clean and makes the schema easy to evolve.
"""

from __future__ import annotations

from typing import Optional


def hint_chmod(mode: str, path: str) -> dict:
    """Restrict file permissions, e.g. `chmod 600 /path/to/file`."""
    return {
        "action": "chmod",
        "args": [mode, str(path)],
    }


def hint_migrate_to_env(env_vars: list[str], source: str) -> dict:
    """Move secret out of a config/plaintext file into an environment variable."""
    return {
        "action": "migrate_to_env",
        "env_vars": list(env_vars),
        "source": str(source),
    }


def hint_change_config_value(target: str, new_value, source: str) -> dict:
    """Update a specific config field. `target` is a dotted path (e.g. 'server.host')."""
    return {
        "action": "change_config_value",
        "target": target,
        "new_value": new_value,
        "source": str(source),
    }


def hint_run_command(commands: list[str], shell: str = "bash") -> dict:
    """Run shell commands. `shell` is 'bash', 'powershell', or 'cmd'."""
    return {
        "action": "run_command",
        "shell": shell,
        "commands": list(commands),
    }


def hint_use_credential_helper(tool: str, helper_options: list[str]) -> dict:
    """Switch to an OS-native credential helper (Docker credsStore, git osxkeychain, etc.)."""
    return {
        "action": "use_credential_helper",
        "tool": tool,
        "helper_options": list(helper_options),
    }


def hint_rotate_credential(provider: str, description: str) -> dict:
    """Rotation is an external action; the hint just tells the AI where to go."""
    return {
        "action": "rotate_credential",
        "provider": provider,
        "description": description,
    }


def hint_manual(description: str, **extra) -> dict:
    """Generic fallback when no structured action applies. Extra kwargs included as-is."""
    d = {
        "action": "manual",
        "description": description,
    }
    if extra:
        d.update(extra)
    return d


def hint_network_bind(service: str, path: Optional[str] = None, port: Optional[int] = None) -> dict:
    """Special case of change_config_value: rebind a service from 0.0.0.0 to 127.0.0.1."""
    hint = {
        "action": "change_config_value",
        "target": "bind_address",
        "new_value": "127.0.0.1",
        "service": service,
    }
    if path:
        hint["source"] = str(path)
    if port is not None:
        hint["port"] = port
    return hint
