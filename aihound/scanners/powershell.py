"""Scanner for PowerShell logs (PSReadLine history + transcripts) for AI credentials."""

from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger("aihound.scanners.powershell")

from aihound.core.scanner import (
    BaseScanner, CredentialFinding, ScanResult, StorageType, RiskLevel,
)
from aihound.core.platform import detect_platform, Platform, get_home, get_wsl_windows_home, get_appdata
from aihound.core.redactor import mask_value, identify_credential_type, KNOWN_PREFIXES
from aihound.core.permissions import (
    get_file_permissions, get_file_owner, assess_risk,
    get_file_mtime, describe_staleness,
)
from aihound.remediation import hint_run_command
from aihound.scanners import register


# Build a regex that matches any known credential prefix followed by the typical
# token body (alphanumeric, dash, underscore, dot, slash, plus — the char set
# used by OAuth tokens, JWTs, API keys, and AWS keys). Minimum length 20 to
# reduce false positives.
_PREFIX_PATTERN = "|".join(re.escape(p) for p in sorted(KNOWN_PREFIXES.keys(), key=len, reverse=True))
_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_\-])((?:" + _PREFIX_PATTERN + r")[A-Za-z0-9_\-./+=]{16,})"
)

# Patterns that commonly precede a secret on the command line, even if the
# secret itself doesn't match a known prefix (e.g. a raw token passed to
# `curl -H "Authorization: Bearer ..."` or `$env:MY_SECRET = "..."`).
_CONTEXT_RE = re.compile(
    r"""(?ix)
    (?:
      (?:api[_-]?key|token|secret|password|passwd|auth[a-z_-]*|bearer)
      \s*[=:]\s*
    |
      \$env:[A-Z_][A-Z0-9_]*\s*=\s*
    |
      -H\s+["']?Authorization:\s*Bearer\s+
    |
      -H\s+["']?x-api-key:\s*
    |
      --api-key\s+
    )
    ["']?([A-Za-z0-9_\-./+=]{20,})["']?
    """
)


@register
class PowerShellScanner(BaseScanner):
    def name(self) -> str:
        return "PowerShell Logs"

    def slug(self) -> str:
        return "powershell"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        for path in self._get_log_paths(plat):
            self._scan_log_file(path, result, show_secrets)

        # Transcript files live in Documents (Windows) or ~/Documents (Linux/macOS pwsh)
        for path in self._get_transcript_paths(plat):
            self._scan_log_file(path, result, show_secrets)

        return result

    def _get_log_paths(self, plat: Platform) -> list[Path]:
        """PSReadLine ConsoleHost_history.txt paths across platforms."""
        paths: list[Path] = []
        home = get_home()

        # PowerShell 7+ (cross-platform) on Linux/macOS stores history under XDG
        paths.append(home / ".local" / "share" / "powershell" / "PSReadLine" / "ConsoleHost_history.txt")
        paths.append(home / ".config" / "powershell" / "PSReadLine" / "ConsoleHost_history.txt")

        # Windows native: %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
        if plat == Platform.WINDOWS:
            appdata = get_appdata()
            if appdata:
                paths.append(appdata / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt")

        # WSL: both Linux-side pwsh and Windows-side PowerShell
        if plat == Platform.WSL:
            win_home = get_wsl_windows_home()
            if win_home:
                paths.append(win_home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt")
                # pwsh 7 on Windows stores under Documents\PowerShell by default but
                # PSReadLine history follows the AppData path above.

        return paths

    def _get_transcript_paths(self, plat: Platform) -> list[Path]:
        """PowerShell transcript files (Start-Transcript output).

        Transcripts go to ~/Documents/ by default with names like
        PowerShell_transcript.HOST.RANDOM.DATETIME.txt.
        """
        roots: list[Path] = []
        home = get_home()
        roots.append(home / "Documents")
        roots.append(home / "OneDrive" / "Documents")

        if plat == Platform.WSL:
            win_home = get_wsl_windows_home()
            if win_home:
                roots.append(win_home / "Documents")
                roots.append(win_home / "OneDrive" / "Documents")

        paths: list[Path] = []
        for root in roots:
            if not root.exists() or not root.is_dir():
                continue
            try:
                # Limit to the root dir (non-recursive) to keep scans fast
                for p in root.glob("PowerShell_transcript.*.txt"):
                    paths.append(p)
            except OSError as e:
                logger.debug("Failed to glob transcripts in %s: %s", root, e)
        return paths

    def _scan_log_file(
        self, path: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        if not path.exists():
            logger.debug("PowerShell log not found: %s", path)
            return

        logger.debug("Scanning PowerShell log: %s", path)
        perms = get_file_permissions(path)
        owner = get_file_owner(path)
        mtime = get_file_mtime(path)
        storage = StorageType.PLAINTEXT_FILE

        try:
            # Use errors='replace' because PSReadLine history files can contain
            # non-UTF-8 bytes (pasted characters, terminal escape sequences)
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.warning("Failed to read %s: %s", path, e)
            result.errors.append(f"Failed to read {path}: {e}")
            return

        seen_values: set[str] = set()

        # Pass 1: Known-prefix matches. High confidence.
        for line_num, line in enumerate(text.splitlines(), 1):
            for match in _TOKEN_RE.finditer(line):
                value = match.group(1)
                if value in seen_values:
                    continue
                seen_values.add(value)
                self._add_finding(
                    result=result,
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
                )

        # Pass 2: Context-based matches (e.g., $env:API_KEY = "..."). Medium confidence.
        for line_num, line in enumerate(text.splitlines(), 1):
            for match in _CONTEXT_RE.finditer(line):
                value = match.group(1)
                if value in seen_values:
                    continue
                # Filter out obvious non-secrets
                if self._looks_like_secret(value):
                    seen_values.add(value)
                    self._add_finding(
                        result=result,
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
                    )

    def _add_finding(
        self, *, result: ScanResult, path: Path, value: str, line_num: int,
        line_text: str, perms, owner, mtime, storage, show_secrets: bool,
        confidence: str,
    ) -> None:
        cred_type = identify_credential_type(value) or "command-line-secret"

        notes = [f"Line {line_num}: {self._truncate_line(line_text)}"]
        if mtime:
            notes.append(f"File last modified: {describe_staleness(mtime)}")
        if confidence == "context":
            notes.append("Detected via context pattern (medium confidence)")

        # PowerShell history is read-only user data by default but may be
        # world-readable on WSL /mnt/c paths. assess_risk handles this.
        risk = assess_risk(storage, path)
        # Bump to CRITICAL if it's a known credential prefix since those are
        # almost certainly real credentials, not false positives.
        if confidence == "known-prefix" and risk != RiskLevel.CRITICAL:
            risk = RiskLevel.HIGH if risk != RiskLevel.INFO else RiskLevel.MEDIUM

        result.findings.append(CredentialFinding(
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
            remediation=(
                "Clear PowerShell history (Remove-Item (Get-PSReadLineOption).HistorySavePath), "
                "rotate the exposed credential, and consider Set-PSReadLineOption -HistorySaveStyle SaveNothing "
                "for sessions that handle secrets"
            ),
            remediation_hint=hint_run_command(
                [
                    "Remove-Item (Get-PSReadLineOption).HistorySavePath",
                    "Set-PSReadLineOption -HistorySaveStyle SaveNothing",
                ],
                shell="powershell",
            ),
            notes=notes,
        ))

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
        # Mostly non-alphanumeric (e.g., pasted JSON, command fragments)
        alnum = sum(1 for c in value if c.isalnum())
        if alnum / len(value) < 0.75:
            return False
        return True
