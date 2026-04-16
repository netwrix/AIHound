"""Scanner for Jupyter notebook/server configuration and kernel specs."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path

from aihound.core.scanner import (
    BaseScanner, CredentialFinding, ScanResult, StorageType, RiskLevel,
)
from aihound.core.platform import (
    detect_platform, Platform, get_home, get_appdata, get_wsl_windows_home,
)
from aihound.core.redactor import mask_value
from aihound.core.permissions import (
    get_file_permissions, get_file_owner, assess_risk,
    get_file_mtime, describe_staleness,
)
from aihound.remediation import hint_change_config_value, hint_migrate_to_env
from aihound.scanners import register

logger = logging.getLogger("aihound.scanners.jupyter")

# Regex for Python-style Jupyter config assignments:
#   c.NotebookApp.token = '...'
#   c.ServerApp.password = "..."
PY_CONFIG_RE = re.compile(
    r"""c\.(?:NotebookApp|ServerApp|Notebook)\.(token|password)\s*=\s*(['"])([^'"]*)\2""",
    re.IGNORECASE,
)

TOKEN_REMEDIATION = (
    "Set a strong token or password hash; avoid binding to 0.0.0.0 "
    "or use an authentication proxy"
)
KERNEL_REMEDIATION = (
    "Move API keys out of kernel.json env; use environment variables "
    "or secret managers"
)


@register
class JupyterScanner(BaseScanner):
    def name(self) -> str:
        return "Jupyter"

    def slug(self) -> str:
        return "jupyter"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        # Config files (py and json variants)
        for path in self._get_config_paths(plat):
            if path.suffix == ".py":
                self._scan_py_config(path, result, show_secrets)
            elif path.suffix == ".json":
                self._scan_json_config(path, result, show_secrets)

        # Kernel specs
        for kernel_path in self._get_kernel_paths(plat):
            self._scan_kernel_json(kernel_path, result, show_secrets)

        return result

    def _get_config_paths(self, plat: Platform) -> list[Path]:
        paths: list[Path] = []
        home = get_home()

        config_names = [
            "jupyter_notebook_config.py",
            "jupyter_notebook_config.json",
            "jupyter_server_config.py",
            "jupyter_server_config.json",
        ]

        for name in config_names:
            paths.append(home / ".jupyter" / name)

        # WSL: also check Windows-side .jupyter
        if plat == Platform.WSL:
            win_home = get_wsl_windows_home()
            if win_home:
                for name in config_names:
                    paths.append(win_home / ".jupyter" / name)

        # On Windows, Jupyter may also store config in %APPDATA%/jupyter
        if plat in (Platform.WINDOWS, Platform.WSL):
            appdata = get_appdata()
            if appdata:
                for name in config_names:
                    paths.append(appdata / "jupyter" / name)

        return paths

    def _get_kernel_paths(self, plat: Platform) -> list[Path]:
        """Return all kernel.json files found under known Jupyter kernels dirs."""
        home = get_home()
        kernel_files: list[Path] = []

        base_dirs: list[Path] = [home / ".local" / "share" / "jupyter" / "kernels"]

        if plat == Platform.WSL:
            win_home = get_wsl_windows_home()
            if win_home:
                # Windows typically uses %APPDATA%/jupyter/kernels
                base_dirs.append(win_home / "AppData" / "Roaming" / "jupyter" / "kernels")

        if plat in (Platform.WINDOWS, Platform.WSL):
            appdata = get_appdata()
            if appdata:
                base_dirs.append(appdata / "jupyter" / "kernels")

        if plat == Platform.MACOS:
            base_dirs.append(home / "Library" / "Jupyter" / "kernels")

        for base in base_dirs:
            if not base.exists():
                continue
            try:
                for sub in base.iterdir():
                    if sub.is_dir():
                        kj = sub / "kernel.json"
                        if kj.exists():
                            kernel_files.append(kj)
            except OSError as e:
                logger.debug("Could not list %s: %s", base, e)

        return kernel_files

    # ------------------------------------------------------------------
    # Python config files (jupyter_*_config.py)
    # ------------------------------------------------------------------
    def _scan_py_config(
        self, path: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        if not path.exists():
            return

        logger.debug("Reading jupyter py config: %s", path)
        perms = get_file_permissions(path)
        owner = get_file_owner(path)
        mtime = get_file_mtime(path)

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.warning("Failed to read %s: %s", path, e)
            result.errors.append(f"Failed to read {path}: {e}")
            return

        storage = StorageType.PLAINTEXT_FILE
        for match in PY_CONFIG_RE.finditer(content):
            field = match.group(1).lower()  # "token" or "password"
            value = match.group(3)

            # Skip empty assignments (e.g. c.NotebookApp.token = '')
            # — still report, because empty token means fully-open server.
            notes = [f"Jupyter {field} set in Python config"]
            if mtime:
                notes.append(f"File last modified: {describe_staleness(mtime)}")
            if value == "":
                notes.append(
                    "Value is EMPTY — the Jupyter server accepts connections "
                    "without authentication"
                )
                risk = RiskLevel.CRITICAL
                preview = "<empty>"
                raw = None
            else:
                risk = assess_risk(storage, path)
                preview = mask_value(value, show_full=show_secrets)
                raw = value if show_secrets else None

            result.findings.append(CredentialFinding(
                tool_name=self.name(),
                credential_type=f"jupyter_{field}",
                storage_type=storage,
                location=str(path),
                exists=True,
                risk_level=risk,
                value_preview=preview,
                raw_value=raw,
                file_permissions=perms,
                file_owner=owner,
                file_modified=mtime,
                remediation=TOKEN_REMEDIATION,
                remediation_hint=hint_change_config_value(
                    field, "<strong-random-string>", str(path)
                ),
                notes=notes,
            ))

    # ------------------------------------------------------------------
    # JSON config files (jupyter_*_config.json)
    # ------------------------------------------------------------------
    def _scan_json_config(
        self, path: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        if not path.exists():
            return

        logger.debug("Reading jupyter json config: %s", path)
        perms = get_file_permissions(path)
        owner = get_file_owner(path)
        mtime = get_file_mtime(path)

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to parse %s: %s", path, e)
            result.errors.append(f"Failed to parse {path}: {e}")
            return

        if not isinstance(data, dict):
            return

        storage = StorageType.PLAINTEXT_JSON
        # Structure is typically { "NotebookApp": { "token": "...", "password": "..." } }
        for section_name in ("NotebookApp", "ServerApp", "Notebook"):
            section = data.get(section_name)
            if not isinstance(section, dict):
                continue
            for field in ("token", "password"):
                value = section.get(field)
                if value is None:
                    continue
                if not isinstance(value, str):
                    continue

                notes = [f"Jupyter {section_name}.{field} in JSON config"]
                if mtime:
                    notes.append(f"File last modified: {describe_staleness(mtime)}")
                if value == "":
                    notes.append(
                        "Value is EMPTY — the Jupyter server accepts connections "
                        "without authentication"
                    )
                    risk = RiskLevel.CRITICAL
                    preview = "<empty>"
                    raw = None
                else:
                    risk = assess_risk(storage, path)
                    preview = mask_value(value, show_full=show_secrets)
                    raw = value if show_secrets else None

                result.findings.append(CredentialFinding(
                    tool_name=self.name(),
                    credential_type=f"jupyter_{field}",
                    storage_type=storage,
                    location=str(path),
                    exists=True,
                    risk_level=risk,
                    value_preview=preview,
                    raw_value=raw,
                    file_permissions=perms,
                    file_owner=owner,
                    file_modified=mtime,
                    remediation=TOKEN_REMEDIATION,
                    remediation_hint=hint_change_config_value(
                        field, "<strong-random-string>", str(path)
                    ),
                    notes=notes,
                ))

    # ------------------------------------------------------------------
    # Kernel spec files (kernels/<name>/kernel.json)
    # ------------------------------------------------------------------
    def _scan_kernel_json(
        self, path: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        logger.debug("Reading kernel.json: %s", path)
        perms = get_file_permissions(path)
        owner = get_file_owner(path)
        mtime = get_file_mtime(path)

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.debug("Could not parse %s: %s", path, e)
            return

        if not isinstance(data, dict):
            return

        env = data.get("env")
        if not isinstance(env, dict):
            return

        kernel_name = path.parent.name
        storage = StorageType.PLAINTEXT_JSON
        staleness_note = f"File last modified: {describe_staleness(mtime)}" if mtime else None

        for env_key, env_value in env.items():
            if not isinstance(env_value, str):
                continue

            if not self._looks_like_secret(env_key, env_value):
                continue

            notes = [f"Kernel: {kernel_name}", f"Env var: {env_key}"]
            if staleness_note:
                notes.append(staleness_note)

            result.findings.append(CredentialFinding(
                tool_name=self.name(),
                credential_type=f"kernel_env:{env_key}",
                storage_type=storage,
                location=str(path),
                exists=True,
                risk_level=assess_risk(storage, path),
                value_preview=mask_value(env_value, show_full=show_secrets),
                raw_value=env_value if show_secrets else None,
                file_permissions=perms,
                file_owner=owner,
                file_modified=mtime,
                remediation=KERNEL_REMEDIATION,
                remediation_hint=hint_migrate_to_env([], str(path)),
                notes=notes,
            ))

    @staticmethod
    def _looks_like_secret(key: str, value: str) -> bool:
        """Heuristic mirroring claude_code.py._looks_like_secret."""
        key_lower = key.lower()
        secret_keywords = [
            "token", "key", "secret", "password", "passwd", "auth",
            "credential", "cred", "api_key", "apikey", "access_key",
        ]
        if any(kw in key_lower for kw in secret_keywords):
            return True

        if len(value) > 20 and not value.startswith("/") and not value.startswith("http"):
            alphanumeric_ratio = sum(c.isalnum() or c in "-_" for c in value) / len(value)
            if alphanumeric_ratio > 0.8:
                return True

        return False
