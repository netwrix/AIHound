"""Scanner for Docker credentials in ~/.docker/config.json."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from aihound.core.scanner import (
    BaseScanner, CredentialFinding, ScanResult, StorageType, RiskLevel,
)
from aihound.core.platform import detect_platform, Platform, get_home, get_wsl_windows_home
from aihound.core.redactor import mask_value
from aihound.core.permissions import (
    get_file_permissions, get_file_owner, assess_risk,
    get_file_mtime, describe_staleness,
)
from aihound.remediation import hint_use_credential_helper
from aihound.scanners import register

logger = logging.getLogger("aihound.scanners.docker")


@register
class DockerScanner(BaseScanner):
    def name(self) -> str:
        return "Docker"

    def slug(self) -> str:
        return "docker"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        for path in self._get_config_paths(plat):
            self._scan_docker_config(path, result, show_secrets)

        return result

    def _get_config_paths(self, plat: Platform) -> list[Path]:
        paths: list[Path] = []
        home = get_home()

        # Docker stores config in ~/.docker/config.json on all platforms
        # (on Windows, that resolves under %USERPROFILE%/.docker/config.json)
        paths.append(home / ".docker" / "config.json")

        if plat == Platform.WSL:
            win_home = get_wsl_windows_home()
            if win_home:
                paths.append(win_home / ".docker" / "config.json")

        return paths

    def _scan_docker_config(
        self, path: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        if not path.exists():
            logger.debug("Docker config not found: %s", path)
            return

        logger.debug("Reading docker config: %s", path)
        perms = get_file_permissions(path)
        owner = get_file_owner(path)
        mtime = get_file_mtime(path)

        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to parse %s: %s", path, e, exc_info=True)
            result.errors.append(f"Failed to parse {path}: {e}")
            return

        if not isinstance(data, dict):
            return

        storage = StorageType.PLAINTEXT_JSON
        staleness_note = f"File last modified: {describe_staleness(mtime)}" if mtime else None

        # 1) auths dict: { "registry": { "auth": "base64(user:pass)", ... } }
        auths = data.get("auths")
        if isinstance(auths, dict):
            for registry, entry in auths.items():
                if not isinstance(entry, dict):
                    continue

                auth_b64 = entry.get("auth")
                if isinstance(auth_b64, str) and auth_b64:
                    notes = [f"Registry: {registry}", "Base64(user:password) stored in plaintext"]
                    if staleness_note:
                        notes.append(staleness_note)
                    result.findings.append(CredentialFinding(
                        tool_name=self.name(),
                        credential_type=f"registry_auth:{registry}",
                        storage_type=storage,
                        location=str(path),
                        exists=True,
                        risk_level=assess_risk(storage, path),
                        value_preview=mask_value(auth_b64, show_full=show_secrets),
                        raw_value=auth_b64 if show_secrets else None,
                        file_permissions=perms,
                        file_owner=owner,
                        file_modified=mtime,
                        remediation=(
                            "Use docker credential helpers (credsStore) instead of "
                            "storing tokens in config.json. See: docker login --help"
                        ),
                        remediation_hint=hint_use_credential_helper(
                            "docker", ["osxkeychain", "pass", "secretservice"]
                        ),
                        notes=notes,
                    ))

                # Sometimes an identitytoken is stored alongside auth
                id_token = entry.get("identitytoken")
                if isinstance(id_token, str) and id_token:
                    notes = [f"Registry: {registry}", "Docker identity token (OAuth refresh-like)"]
                    if staleness_note:
                        notes.append(staleness_note)
                    result.findings.append(CredentialFinding(
                        tool_name=self.name(),
                        credential_type=f"registry_identitytoken:{registry}",
                        storage_type=storage,
                        location=str(path),
                        exists=True,
                        risk_level=assess_risk(storage, path),
                        value_preview=mask_value(id_token, show_full=show_secrets),
                        raw_value=id_token if show_secrets else None,
                        file_permissions=perms,
                        file_owner=owner,
                        file_modified=mtime,
                        remediation=(
                            "Use docker credential helpers (credsStore) instead of "
                            "storing tokens in config.json. See: docker login --help"
                        ),
                        remediation_hint=hint_use_credential_helper(
                            "docker", ["osxkeychain", "pass", "secretservice"]
                        ),
                        notes=notes,
                    ))

                # Any other string values that look like a secret key
                for sub_key, sub_val in entry.items():
                    if sub_key in ("auth", "identitytoken", "email", "username"):
                        continue
                    if isinstance(sub_val, str) and len(sub_val) > 20:
                        lowered = sub_key.lower()
                        if any(k in lowered for k in ("token", "secret", "key", "password")):
                            notes = [f"Registry: {registry}", f"Field: {sub_key}"]
                            if staleness_note:
                                notes.append(staleness_note)
                            result.findings.append(CredentialFinding(
                                tool_name=self.name(),
                                credential_type=f"registry_{sub_key}:{registry}",
                                storage_type=storage,
                                location=str(path),
                                exists=True,
                                risk_level=assess_risk(storage, path),
                                value_preview=mask_value(sub_val, show_full=show_secrets),
                                raw_value=sub_val if show_secrets else None,
                                file_permissions=perms,
                                file_owner=owner,
                                file_modified=mtime,
                                remediation=(
                                    "Use docker credential helpers (credsStore) instead of "
                                    "storing tokens in config.json. See: docker login --help"
                                ),
                                remediation_hint=hint_use_credential_helper(
                                    "docker", ["osxkeychain", "pass", "secretservice"]
                                ),
                                notes=notes,
                            ))

        # 2) credsStore: global credential helper (safer)
        creds_store = data.get("credsStore")
        if isinstance(creds_store, str) and creds_store:
            notes = [
                f"Using credential helper: docker-credential-{creds_store}",
                "Credentials stored outside config.json (likely in OS keystore)",
            ]
            if staleness_note:
                notes.append(staleness_note)
            result.findings.append(CredentialFinding(
                tool_name=self.name(),
                credential_type="credsStore",
                storage_type=StorageType.UNKNOWN,
                location=str(path),
                exists=True,
                risk_level=RiskLevel.INFO,
                value_preview=creds_store,
                file_permissions=perms,
                file_owner=owner,
                file_modified=mtime,
                remediation=(
                    "Use docker credential helpers (credsStore) instead of "
                    "storing tokens in config.json. See: docker login --help"
                ),
                remediation_hint=hint_use_credential_helper(
                    "docker", ["osxkeychain", "pass", "secretservice"]
                ),
                notes=notes,
            ))

        # 3) credHelpers: per-registry credential helpers
        cred_helpers = data.get("credHelpers")
        if isinstance(cred_helpers, dict) and cred_helpers:
            for registry, helper in cred_helpers.items():
                if not isinstance(helper, str):
                    continue
                notes = [
                    f"Registry: {registry}",
                    f"Using credential helper: docker-credential-{helper}",
                    "Credentials stored outside config.json (likely in OS keystore)",
                ]
                if staleness_note:
                    notes.append(staleness_note)
                result.findings.append(CredentialFinding(
                    tool_name=self.name(),
                    credential_type=f"credHelper:{registry}",
                    storage_type=StorageType.UNKNOWN,
                    location=str(path),
                    exists=True,
                    risk_level=RiskLevel.INFO,
                    value_preview=helper,
                    file_permissions=perms,
                    file_owner=owner,
                    file_modified=mtime,
                    remediation=(
                        "Use docker credential helpers (credsStore) instead of "
                        "storing tokens in config.json. See: docker login --help"
                    ),
                    remediation_hint=hint_use_credential_helper(
                        "docker", ["osxkeychain", "pass", "secretservice"]
                    ),
                    notes=notes,
                ))

        # 4) Top-level secret-looking keys (e.g., secretName, proxies with tokens)
        for key, val in data.items():
            if key in ("auths", "credsStore", "credHelpers"):
                continue
            if isinstance(val, str) and len(val) > 20:
                lowered = key.lower()
                if any(k in lowered for k in ("token", "secret", "key", "password", "auth")):
                    notes = [f"Top-level field: {key}"]
                    if staleness_note:
                        notes.append(staleness_note)
                    result.findings.append(CredentialFinding(
                        tool_name=self.name(),
                        credential_type=f"config:{key}",
                        storage_type=storage,
                        location=str(path),
                        exists=True,
                        risk_level=assess_risk(storage, path),
                        value_preview=mask_value(val, show_full=show_secrets),
                        raw_value=val if show_secrets else None,
                        file_permissions=perms,
                        file_owner=owner,
                        file_modified=mtime,
                        remediation=(
                            "Use docker credential helpers (credsStore) instead of "
                            "storing tokens in config.json. See: docker login --help"
                        ),
                        remediation_hint=hint_use_credential_helper(
                            "docker", ["osxkeychain", "pass", "secretservice"]
                        ),
                        notes=notes,
                    ))
            elif isinstance(val, dict):
                # Recurse one level (e.g., "proxies", "HttpHeaders")
                self._recurse_for_secrets(
                    val, path, perms, owner, mtime, result, show_secrets,
                    prefix=key, staleness_note=staleness_note,
                )

    def _recurse_for_secrets(
        self, data: dict, path: Path, perms, owner, mtime,
        result: ScanResult, show_secrets: bool,
        prefix: str, staleness_note: str | None,
        depth: int = 0,
    ) -> None:
        if depth > 4:
            return
        storage = StorageType.PLAINTEXT_JSON
        for key, val in data.items():
            full_key = f"{prefix}.{key}"
            if isinstance(val, dict):
                self._recurse_for_secrets(
                    val, path, perms, owner, mtime, result, show_secrets,
                    prefix=full_key, staleness_note=staleness_note, depth=depth + 1,
                )
            elif isinstance(val, str) and len(val) > 20:
                lowered = key.lower()
                if any(k in lowered for k in ("token", "secret", "key", "password", "auth")):
                    notes = [f"Nested field: {full_key}"]
                    if staleness_note:
                        notes.append(staleness_note)
                    result.findings.append(CredentialFinding(
                        tool_name=self.name(),
                        credential_type=f"config:{full_key}",
                        storage_type=storage,
                        location=str(path),
                        exists=True,
                        risk_level=assess_risk(storage, path),
                        value_preview=mask_value(val, show_full=show_secrets),
                        raw_value=val if show_secrets else None,
                        file_permissions=perms,
                        file_owner=owner,
                        file_modified=mtime,
                        remediation=(
                            "Use docker credential helpers (credsStore) instead of "
                            "storing tokens in config.json. See: docker login --help"
                        ),
                        remediation_hint=hint_use_credential_helper(
                            "docker", ["osxkeychain", "pass", "secretservice"]
                        ),
                        notes=notes,
                    ))
