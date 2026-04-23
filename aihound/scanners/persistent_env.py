"""Scanner for OS-level persistent environment variable stores.

Covers:
- Linux/WSL: /etc/environment, /etc/profile.d/*.sh, ~/.pam_environment,
  ~/.config/environment.d/*.conf
- macOS: ~/Library/LaunchAgents/*.plist, /Library/LaunchDaemons/*.plist,
  /etc/launchd.conf
- Windows/WSL: HKCU\\Environment and HKLM\\...\\Environment via reg.exe
"""

from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger("aihound.scanners.persistent_env")

from aihound.core.scanner import (
    BaseScanner,
    CredentialFinding,
    ScanResult,
    StorageType,
    RiskLevel,
)
from aihound.core.platform import detect_platform, Platform, get_home, get_wsl_windows_home
from aihound.core.redactor import mask_value, identify_credential_type, KNOWN_PREFIXES
from aihound.core.permissions import (
    get_file_permissions,
    get_file_owner,
    get_file_mtime,
    describe_staleness,
)
from aihound.remediation import hint_manual, hint_run_command
from aihound.scanners import register
from aihound.scanners.envvars import AI_ENV_VARS

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_PROFILE_D_SIZE = 65536  # 64KB

# ---------------------------------------------------------------------------
# Compiled regex patterns
# ---------------------------------------------------------------------------

# /etc/environment and environment.d: VAR=value (no "export" prefix)
_KV_RE = re.compile(
    r"""(?mx)^ \s* ([A-Z_][A-Z0-9_]*) \s* = \s* ["']? ([^"'\s#]+) ["']?"""
)

# profile.d / launchd.conf: export VAR=value
_EXPORT_RE = re.compile(
    r"""(?mx)^ \s* export \s+ ([A-Z_][A-Z0-9_]*) \s* = \s* ["']? ([^"'\s#]+) ["']?"""
)

# ~/.pam_environment: VAR DEFAULT=value  or  VAR OVERRIDE=value
_PAM_RE = re.compile(
    r"""(?mx)^ \s* ([A-Z_][A-Z0-9_]*) \s+ (?:DEFAULT|OVERRIDE) \s* = \s* ["']? ([^"'\s#]+) ["']?"""
)

# reg.exe query output:    NAME    REG_SZ    VALUE
_REG_LINE_RE = re.compile(
    r"^\s+(\S+)\s+REG_(?:SZ|EXPAND_SZ)\s+(.+)$", re.MULTILINE
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _is_ai_relevant(var_name: str, value: str) -> bool:
    """Return True if var_name is known AI cred or value matches a known prefix."""
    if var_name in AI_ENV_VARS:
        return True
    if identify_credential_type(value):
        return True
    return False


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

@register
class PersistentEnvScanner(BaseScanner):
    """Scan OS-level persistent environment variable stores."""

    def name(self) -> str:
        return "Persistent Environment"

    def slug(self) -> str:
        return "persistent-env"

    # ------------------------------------------------------------------
    # Public scan entry point
    # ------------------------------------------------------------------

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        if plat in (Platform.LINUX, Platform.WSL):
            self._scan_linux(result, show_secrets)
        elif plat == Platform.MACOS:
            self._scan_macos(result, show_secrets)
        elif plat == Platform.WINDOWS:
            self._scan_windows_registry(result, show_secrets)

        # On WSL also check the Windows registry
        if plat == Platform.WSL:
            self._scan_windows_registry(result, show_secrets)

        return result

    # ------------------------------------------------------------------
    # Linux / WSL scanning
    # ------------------------------------------------------------------

    def _scan_linux(self, result: ScanResult, show_secrets: bool) -> None:
        # /etc/environment — system-wide key=value
        etc_env = Path("/etc/environment")
        text = self._read_file(etc_env, result)
        if text is not None:
            findings = self._scan_kv_content(text, etc_env, show_secrets, is_system=True)
            result.findings.extend(findings)

        # /etc/profile.d/*.sh — system-wide shell scripts
        profile_d = Path("/etc/profile.d")
        if profile_d.is_dir():
            for sh_file in sorted(profile_d.glob("*.sh")):
                try:
                    size = sh_file.stat().st_size
                except OSError:
                    continue
                if size > _MAX_PROFILE_D_SIZE:
                    logger.debug("Skipping large profile.d file: %s (%d bytes)", sh_file, size)
                    result.errors.append(f"Skipped (>64KB): {sh_file}")
                    continue
                text = self._read_file(sh_file, result)
                if text is not None:
                    findings = self._scan_export_content(text, sh_file, show_secrets, is_system=True)
                    result.findings.extend(findings)

        # ~/.pam_environment — user-level PAM
        pam_env = get_home() / ".pam_environment"
        text = self._read_file(pam_env, result)
        if text is not None:
            findings = self._scan_pam_content(text, pam_env, show_secrets)
            result.findings.extend(findings)

        # ~/.config/environment.d/*.conf — systemd user env
        env_d = get_home() / ".config" / "environment.d"
        if env_d.is_dir():
            for conf_file in sorted(env_d.glob("*.conf")):
                text = self._read_file(conf_file, result)
                if text is not None:
                    findings = self._scan_kv_content(text, conf_file, show_secrets, is_system=False)
                    result.findings.extend(findings)

    # ------------------------------------------------------------------
    # macOS scanning
    # ------------------------------------------------------------------

    def _scan_macos(self, result: ScanResult, show_secrets: bool) -> None:
        import plistlib

        # ~/Library/LaunchAgents/*.plist — user-level
        user_agents = get_home() / "Library" / "LaunchAgents"
        if user_agents.is_dir():
            for plist_file in sorted(user_agents.glob("*.plist")):
                self._scan_plist_file(plist_file, result, show_secrets, is_system=False)

        # /Library/LaunchDaemons/*.plist — system-level
        sys_daemons = Path("/Library/LaunchDaemons")
        if sys_daemons.is_dir():
            for plist_file in sorted(sys_daemons.glob("*.plist")):
                self._scan_plist_file(plist_file, result, show_secrets, is_system=True)

        # /etc/launchd.conf — deprecated export-style
        launchd_conf = Path("/etc/launchd.conf")
        text = self._read_file(launchd_conf, result)
        if text is not None:
            findings = self._scan_export_content(text, launchd_conf, show_secrets, is_system=True)
            result.findings.extend(findings)

    def _scan_plist_file(
        self, path: Path, result: ScanResult, show_secrets: bool, is_system: bool
    ) -> None:
        import plistlib

        try:
            with open(path, "rb") as fh:
                data = plistlib.load(fh)
        except Exception as exc:
            logger.debug("Could not parse plist %s: %s", path, exc)
            return

        if not isinstance(data, dict):
            return

        env_dict = data.get("EnvironmentVariables")
        if not isinstance(env_dict, dict):
            return

        findings = self._scan_plist_env_dict(env_dict, path, show_secrets, is_system=is_system)
        result.findings.extend(findings)

    # ------------------------------------------------------------------
    # Windows registry scanning
    # ------------------------------------------------------------------

    def _scan_windows_registry(self, result: ScanResult, show_secrets: bool) -> None:
        hkcu_key = r"HKCU\Environment"
        hklm_key = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment"

        output = self._query_registry(hkcu_key, result)
        if output is not None:
            findings = self._parse_reg_output(output, hkcu_key, show_secrets, is_system=False)
            result.findings.extend(findings)

        output = self._query_registry(hklm_key, result)
        if output is not None:
            findings = self._parse_reg_output(output, hklm_key, show_secrets, is_system=True)
            result.findings.extend(findings)

    # ------------------------------------------------------------------
    # Content parsers
    # ------------------------------------------------------------------

    def _scan_kv_content(
        self,
        text: str,
        path: Path,
        show_secrets: bool,
        is_system: bool,
    ) -> list[CredentialFinding]:
        findings: list[CredentialFinding] = []
        for line_num, match in self._matches_with_line_numbers(text, _KV_RE):
            var_name, value = match.group(1), match.group(2).strip()
            if not _is_ai_relevant(var_name, value):
                continue
            findings.append(
                self._make_file_finding(var_name, value, path, line_num, show_secrets, is_system)
            )
        return findings

    def _scan_export_content(
        self,
        text: str,
        path: Path,
        show_secrets: bool,
        is_system: bool,
    ) -> list[CredentialFinding]:
        findings: list[CredentialFinding] = []
        for line_num, match in self._matches_with_line_numbers(text, _EXPORT_RE):
            var_name, value = match.group(1), match.group(2).strip()
            if not _is_ai_relevant(var_name, value):
                continue
            findings.append(
                self._make_file_finding(var_name, value, path, line_num, show_secrets, is_system)
            )
        return findings

    def _scan_pam_content(
        self,
        text: str,
        path: Path,
        show_secrets: bool,
    ) -> list[CredentialFinding]:
        findings: list[CredentialFinding] = []
        for line_num, match in self._matches_with_line_numbers(text, _PAM_RE):
            var_name, value = match.group(1), match.group(2).strip()
            if not _is_ai_relevant(var_name, value):
                continue
            # ~/.pam_environment is always user-level (HIGH)
            findings.append(
                self._make_file_finding(
                    var_name,
                    value,
                    path,
                    line_num,
                    show_secrets,
                    is_system=False,
                    storage_override=StorageType.PLAINTEXT_ENV,
                )
            )
        return findings

    def _scan_plist_env_dict(
        self,
        env_dict: dict,
        path: Path,
        show_secrets: bool,
        is_system: bool,
    ) -> list[CredentialFinding]:
        findings: list[CredentialFinding] = []
        for var_name, value in env_dict.items():
            if not isinstance(value, str):
                continue
            if not _is_ai_relevant(var_name, value):
                continue

            cred_type = identify_credential_type(value) or AI_ENV_VARS.get(var_name, var_name)
            risk = RiskLevel.CRITICAL if is_system else RiskLevel.HIGH
            notes = [f"Found {var_name} in EnvironmentVariables dict of {path.name}"]

            findings.append(
                CredentialFinding(
                    tool_name=self.name(),
                    credential_type=cred_type,
                    storage_type=StorageType.PLAINTEXT_FILE,
                    location=str(path),
                    exists=True,
                    risk_level=risk,
                    value_preview=mask_value(value, show_full=show_secrets),
                    raw_value=value if show_secrets else None,
                    file_permissions=get_file_permissions(path),
                    file_owner=get_file_owner(path),
                    file_modified=get_file_mtime(path),
                    notes=notes,
                    remediation="Remove credential from persistent environment store and use a secret manager",
                    remediation_hint=hint_manual(
                        "Remove credential from persistent environment store and use a secret manager",
                        suggested_tools=["1Password CLI", "doppler", "vault"],
                    ),
                )
            )
        return findings

    def _parse_reg_output(
        self,
        output: str,
        reg_key: str,
        show_secrets: bool,
        is_system: bool,
    ) -> list[CredentialFinding]:
        findings: list[CredentialFinding] = []
        for match in _REG_LINE_RE.finditer(output):
            var_name = match.group(1).strip()
            value = match.group(2).strip()
            if not _is_ai_relevant(var_name, value):
                continue

            cred_type = identify_credential_type(value) or AI_ENV_VARS.get(var_name, var_name)
            risk = RiskLevel.CRITICAL if is_system else RiskLevel.HIGH
            scope = "Machine" if is_system else "User"
            ps_cmd = f"[System.Environment]::SetEnvironmentVariable('{var_name}', $null, '{scope}')"

            findings.append(
                CredentialFinding(
                    tool_name=self.name(),
                    credential_type=cred_type,
                    storage_type=StorageType.PLAINTEXT_INI,
                    location=f"{reg_key}\\{var_name}",
                    exists=True,
                    risk_level=risk,
                    value_preview=mask_value(value, show_full=show_secrets),
                    raw_value=value if show_secrets else None,
                    notes=[f"Registry key: {reg_key}"],
                    remediation="Remove credential from Windows registry environment and use a secret manager",
                    remediation_hint=hint_run_command(
                        [ps_cmd],
                        shell="powershell",
                    ),
                )
            )
        return findings

    # ------------------------------------------------------------------
    # Low-level helpers
    # ------------------------------------------------------------------

    def _read_file(self, path: Path, result: ScanResult) -> Optional[str]:
        """Read a file, returning its text or None (adding to errors on failure)."""
        if not path.exists():
            return None
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except PermissionError:
            result.errors.append(f"Permission denied: {path}")
        except OSError as exc:
            result.errors.append(f"Could not read {path}: {exc}")
        return None

    def _query_registry(self, key: str, result: ScanResult) -> Optional[str]:
        """Run reg.exe query and return stdout, or None on failure."""
        try:
            proc = subprocess.run(
                ["reg.exe", "query", key],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return proc.stdout
        except FileNotFoundError:
            # reg.exe not available (pure Linux)
            return None
        except subprocess.TimeoutExpired:
            result.errors.append(f"Timeout querying registry key: {key}")
            return None
        except OSError as exc:
            result.errors.append(f"OSError querying registry key {key}: {exc}")
            return None

    def _make_file_finding(
        self,
        var_name: str,
        value: str,
        path: Path,
        line_num: int,
        show_secrets: bool,
        is_system: bool,
        storage_override: Optional[StorageType] = None,
    ) -> CredentialFinding:
        cred_type = identify_credential_type(value) or AI_ENV_VARS.get(var_name, var_name)
        risk = RiskLevel.CRITICAL if is_system else RiskLevel.HIGH
        storage = storage_override if storage_override is not None else StorageType.PLAINTEXT_FILE
        notes = [f"Found {var_name} at line {line_num} in {path}"]

        return CredentialFinding(
            tool_name=self.name(),
            credential_type=cred_type,
            storage_type=storage,
            location=f"{path}:{line_num}",
            exists=True,
            risk_level=risk,
            value_preview=mask_value(value, show_full=show_secrets),
            raw_value=value if show_secrets else None,
            file_permissions=get_file_permissions(path),
            file_owner=get_file_owner(path),
            file_modified=get_file_mtime(path),
            notes=notes,
            remediation="Remove credential from persistent environment store and use a secret manager",
            remediation_hint=hint_manual(
                "Remove credential from persistent environment store and use a secret manager",
                suggested_tools=["1Password CLI", "doppler", "vault"],
            ),
        )

    @staticmethod
    def _matches_with_line_numbers(
        text: str, pattern: re.Pattern
    ) -> list[tuple[int, re.Match]]:
        """Return (1-based line number, match) pairs for all regex matches in text."""
        results = []
        for match in pattern.finditer(text):
            line_num = text.count("\n", 0, match.start()) + 1
            results.append((line_num, match))
        return results
