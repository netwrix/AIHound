"""Scanner for shell history files (bash, zsh, fish) for AI credentials."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

logger = logging.getLogger("aihound.scanners.shell_history")

from aihound.core.scanner import (
    BaseScanner, CredentialFinding, ScanResult, StorageType, RiskLevel,
)
from aihound.core.platform import detect_platform, Platform, get_home
from aihound.core.redactor import mask_value, identify_credential_type, KNOWN_PREFIXES, redact_line
from aihound.core.permissions import (
    get_file_permissions, get_file_owner, assess_risk,
    get_file_mtime, describe_staleness,
)
from aihound.remediation import hint_run_command
from aihound.scanners import register

_MAX_HISTORY_SIZE = 50 * 1024 * 1024  # 50 MB


# Pass 1: Known-prefix pattern — high confidence
_PREFIX_PATTERN = "|".join(re.escape(p) for p in sorted(KNOWN_PREFIXES.keys(), key=len, reverse=True))
_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_\-])((?:" + _PREFIX_PATTERN + r")[A-Za-z0-9_\-./+=]{16,})"
)

# Pass 2: Context-based pattern — medium confidence
_CONTEXT_RE = re.compile(
    r"""(?ix)
    (?:
      (?:api[_-]?key|token|secret|password|passwd|auth[a-z_-]*|bearer)\s*[=:]\s*
    | export\s+[A-Z_][A-Z0-9_]*\s*=\s*
    | -H\s+["']?Authorization:\s*Bearer\s+
    | -H\s+["']?x-api-key:\s*
    | --api-key\s+
    | --token\s+
    )
    ["']?([A-Za-z0-9_\-./+=]{20,})["']?
"""
)

# Per-shell remediation configuration
_SHELL_REMEDIATION = {
    "bash": {
        "commands": ["rm ~/.bash_history", "history -c"],
        "shell": "bash",
        "human": (
            "Clear bash history (rm ~/.bash_history && history -c), rotate the exposed credential, "
            "and consider HISTIGNORE for future sessions"
        ),
    },
    "zsh": {
        "commands": ["rm ~/.zsh_history", "fc -p /dev/null"],
        "shell": "zsh",
        "human": (
            "Clear zsh history (rm ~/.zsh_history), rotate the exposed credential, "
            "and consider setopt HIST_IGNORE_SPACE for future sessions"
        ),
    },
    "fish": {
        "commands": ["rm ~/.local/share/fish/fish_history", "builtin history clear"],
        "shell": "fish",
        "human": (
            "Clear fish history (rm ~/.local/share/fish/fish_history), rotate the exposed credential, "
            "and consider --private for future sessions"
        ),
    },
}


def _detect_shell(path: Path) -> str:
    """Detect shell type from history file path."""
    path_str = str(path)
    name = path.name
    if "fish" in path_str:
        return "fish"
    if "zsh" in name or name == ".zhistory":
        return "zsh"
    return "bash"


@register
class ShellHistoryScanner(BaseScanner):
    def name(self) -> str:
        return "Shell History"

    def slug(self) -> str:
        return "shell-history"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        # Skip on Windows — PowerShell scanner covers it
        if plat == Platform.WINDOWS:
            return result

        for path in self._get_history_paths(plat):
            if not path.exists():
                logger.debug("Shell history not found: %s", path)
                continue

            logger.debug("Scanning shell history: %s", path)
            try:
                file_size = path.stat().st_size
                if file_size > _MAX_HISTORY_SIZE:
                    logger.warning(
                        "Skipping %s: file size %d bytes exceeds %d byte limit",
                        path, file_size, _MAX_HISTORY_SIZE,
                    )
                    result.errors.append(
                        f"Skipped {path}: file too large ({file_size} bytes, limit {_MAX_HISTORY_SIZE})"
                    )
                    continue
            except OSError as e:
                logger.warning("Failed to stat %s: %s", path, e)
                result.errors.append(f"Failed to stat {path}: {e}")
                continue

            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as e:
                logger.warning("Failed to read %s: %s", path, e)
                result.errors.append(f"Failed to read {path}: {e}")
                continue

            findings = self._scan_history_content(text, path, show_secrets)
            result.findings.extend(findings)

        return result

    def _get_history_paths(self, plat: Platform) -> list[Path]:
        """Return candidate shell history file paths for Linux/macOS/WSL."""
        if plat == Platform.WINDOWS:
            return []

        home = get_home()
        paths: list[Path] = [
            home / ".bash_history",
            home / ".zsh_history",
            home / ".zhistory",
            home / ".local" / "share" / "fish" / "fish_history",
        ]

        # Respect ZDOTDIR for zsh
        zdotdir = os.environ.get("ZDOTDIR")
        if zdotdir:
            zdot_history = Path(zdotdir) / ".zsh_history"
            if zdot_history not in paths:
                paths.append(zdot_history)

        return paths

    def _scan_history_content(
        self, text: str, path: Path, show_secrets: bool
    ) -> list[CredentialFinding]:
        """Scan history text and return a list of CredentialFindings."""
        findings: list[CredentialFinding] = []
        seen_values: set[str] = set()

        shell = _detect_shell(path)
        storage = StorageType.PLAINTEXT_FILE

        # Collect file metadata if the file exists
        perms = get_file_permissions(path) if path.exists() else None
        owner = get_file_owner(path) if path.exists() else None
        mtime = get_file_mtime(path) if path.exists() else None

        lines = text.splitlines()

        # Pass 1: Known-prefix matches — high confidence
        for line_num, line in enumerate(lines, 1):
            for match in _TOKEN_RE.finditer(line):
                value = match.group(1)
                if value in seen_values:
                    continue
                seen_values.add(value)
                findings.append(self._make_finding(
                    path=path,
                    value=value,
                    line_num=line_num,
                    line_text=line,
                    perms=perms,
                    owner=owner,
                    mtime=mtime,
                    storage=storage,
                    show_secrets=show_secrets,
                    confidence="known-prefix",
                    shell=shell,
                ))

        # Pass 2: Context-based matches — medium confidence
        for line_num, line in enumerate(lines, 1):
            for match in _CONTEXT_RE.finditer(line):
                value = match.group(1)
                if value in seen_values:
                    continue
                if self._looks_like_secret(value):
                    seen_values.add(value)
                    findings.append(self._make_finding(
                        path=path,
                        value=value,
                        line_num=line_num,
                        line_text=line,
                        perms=perms,
                        owner=owner,
                        mtime=mtime,
                        storage=storage,
                        show_secrets=show_secrets,
                        confidence="context",
                        shell=shell,
                    ))

        return findings

    def _make_finding(
        self, *, path: Path, value: str, line_num: int, line_text: str,
        perms, owner, mtime, storage: StorageType, show_secrets: bool,
        confidence: str, shell: str,
    ) -> CredentialFinding:
        cred_type = identify_credential_type(value) or "command-line-secret"

        notes = [f"Line {line_num}: {self._truncate_line(redact_line(line_text))}"]
        if mtime:
            notes.append(f"File last modified: {describe_staleness(mtime)}")
        if confidence == "context":
            notes.append("Detected via context pattern (medium confidence)")

        risk = assess_risk(storage, path)
        # Bump to HIGH minimum for known-prefix matches (almost certainly real creds)
        if confidence == "known-prefix" and risk not in (RiskLevel.CRITICAL, RiskLevel.HIGH):
            risk = RiskLevel.HIGH

        rem_cfg = _SHELL_REMEDIATION.get(shell, _SHELL_REMEDIATION["bash"])
        remediation_hint = hint_run_command(
            commands=rem_cfg["commands"],
            shell=rem_cfg["shell"],
        )

        return CredentialFinding(
            tool_name=self.name(),
            credential_type=cred_type,
            storage_type=storage,
            location=f"{path}:{line_num}",
            exists=True,
            risk_level=risk,
            value_preview=mask_value(value, show_full=show_secrets),
            raw_value=value if show_secrets else None,
            file_permissions=perms,
            file_owner=owner,
            file_modified=mtime,
            remediation=rem_cfg["human"],
            remediation_hint=remediation_hint,
            notes=notes,
        )

    @staticmethod
    def _truncate_line(line: str, max_len: int = 120) -> str:
        """Truncate a log line for note display, collapsing whitespace."""
        collapsed = " ".join(line.split())
        if len(collapsed) <= max_len:
            return collapsed
        return collapsed[: max_len - 3] + "..."

    @staticmethod
    def _looks_like_secret(value: str) -> bool:
        """Heuristic to avoid flagging common non-secret strings."""
        if len(value) < 20:
            return False
        # Path-like
        if value.startswith(("/", "\\", ".\\", "./", "C:", "c:")):
            return False
        # URL-like
        if value.startswith(("http://", "https://", "ftp://", "file://")):
            return False
        # Mostly non-alphanumeric
        alnum = sum(1 for c in value if c.isalnum())
        if alnum / len(value) < 0.75:
            return False
        return True
