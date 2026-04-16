"""Scanner for AI tool session data in browser local storage.

Firefox stores localStorage in a plain SQLite database (webappsstore.sqlite)
which is queryable with the standard library. AI providers (Claude.ai,
ChatGPT/OpenAI, Gemini, Copilot, Perplexity, HuggingFace) often keep session
state, conversation caches, and sometimes access/refresh tokens there.

Chromium-based browsers (Chrome, Brave, Edge) use LevelDB for localStorage,
which is not parseable from the Python stdlib. For those we only record an
INFO finding noting that the storage exists.
"""

from __future__ import annotations

import configparser
import logging
import sqlite3
from pathlib import Path
from typing import Optional

from aihound.core.scanner import (
    BaseScanner,
    CredentialFinding,
    ScanResult,
    StorageType,
    RiskLevel,
)
from aihound.core.platform import (
    detect_platform,
    Platform,
    get_home,
    get_appdata,
    get_localappdata,
    get_wsl_windows_home,
)
from aihound.core.redactor import mask_value
from aihound.core.permissions import (
    get_file_permissions,
    get_file_owner,
    get_file_mtime,
    describe_staleness,
)
from aihound.remediation import hint_chmod, hint_manual
from aihound.scanners import register

logger = logging.getLogger("aihound.scanners.browser_sessions")


# Domains of interest — Firefox originKey is a reversed-domain string like
# "moc.ia-edualc.:https:443" so we match on the reversed substring as well.
AI_DOMAINS = [
    "claude.ai",
    "openai.com",
    "chatgpt.com",
    "gemini.google.com",
    "copilot.microsoft.com",
    "perplexity.ai",
    "huggingface.co",
]


SESSION_COOKIE_KEYWORDS = ("session", "auth", "token")


@register
class BrowserSessionsScanner(BaseScanner):
    def name(self) -> str:
        return "Browser Sessions"

    def slug(self) -> str:
        return "browser-sessions"

    def is_applicable(self) -> bool:
        return True

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        # Firefox
        for profiles_root in self._get_firefox_profiles_roots(plat):
            try:
                self._scan_firefox_root(profiles_root, result, show_secrets)
            except Exception as e:
                logger.warning("Firefox scan failed for %s: %s", profiles_root, e, exc_info=True)
                result.errors.append(f"Firefox scan failed for {profiles_root}: {e}")

        # Chromium stubs
        for browser_name, local_storage_dir in self._get_chromium_local_storage_dirs(plat):
            try:
                self._record_chromium_stub(browser_name, local_storage_dir, result)
            except Exception as e:
                logger.warning(
                    "Chromium detection failed for %s at %s: %s",
                    browser_name, local_storage_dir, e, exc_info=True,
                )
                result.errors.append(
                    f"Chromium detection failed for {browser_name} at {local_storage_dir}: {e}"
                )

        return result

    # ------------------------------------------------------------------ #
    # Firefox
    # ------------------------------------------------------------------ #

    def _get_firefox_profiles_roots(self, plat: Platform) -> list[Path]:
        """Return candidate directories that contain profiles.ini + profile dirs."""
        roots: list[Path] = []
        home = get_home()

        if plat == Platform.LINUX:
            roots.append(home / ".mozilla" / "firefox")
        elif plat == Platform.MACOS:
            roots.append(home / "Library" / "Application Support" / "Firefox")
        elif plat == Platform.WINDOWS:
            appdata = get_appdata()
            if appdata:
                roots.append(appdata / "Mozilla" / "Firefox")
        elif plat == Platform.WSL:
            # Linux-side Firefox
            roots.append(home / ".mozilla" / "firefox")
            # Windows-side Firefox through /mnt/c
            appdata = get_appdata()
            if appdata:
                roots.append(appdata / "Mozilla" / "Firefox")
            win_home = get_wsl_windows_home()
            if win_home:
                # Some older installs live directly under the user profile
                roots.append(win_home / "AppData" / "Roaming" / "Mozilla" / "Firefox")

        # De-duplicate while preserving order
        seen: set[str] = set()
        unique: list[Path] = []
        for r in roots:
            key = str(r)
            if key not in seen:
                seen.add(key)
                unique.append(r)
        return unique

    def _scan_firefox_root(
        self, profiles_root: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        if not profiles_root.exists():
            logger.debug("Firefox root not found: %s", profiles_root)
            return

        profiles_ini = profiles_root / "profiles.ini"
        profile_dirs = self._parse_firefox_profiles_ini(profiles_ini, profiles_root)

        # Fallback: scan subdirectories that look like profile dirs
        if not profile_dirs:
            logger.debug("No profiles.ini entries; falling back to directory scan at %s", profiles_root)
            candidate_parents = [profiles_root, profiles_root / "Profiles"]
            for parent in candidate_parents:
                if not parent.exists() or not parent.is_dir():
                    continue
                for child in parent.iterdir():
                    if child.is_dir() and (child / "webappsstore.sqlite").exists():
                        profile_dirs.append(child)

        if not profile_dirs:
            logger.debug("No Firefox profiles found under %s", profiles_root)
            return

        for profile_dir in profile_dirs:
            try:
                self._scan_firefox_profile(profile_dir, result, show_secrets)
            except Exception as e:
                logger.warning("Firefox profile scan failed (%s): %s", profile_dir, e, exc_info=True)
                result.errors.append(f"Firefox profile scan failed ({profile_dir}): {e}")

    def _parse_firefox_profiles_ini(
        self, profiles_ini: Path, profiles_root: Path
    ) -> list[Path]:
        if not profiles_ini.exists():
            logger.debug("profiles.ini not found at %s", profiles_ini)
            return []

        parser = configparser.ConfigParser(strict=False, interpolation=None)
        try:
            parser.read(profiles_ini, encoding="utf-8")
        except (configparser.Error, OSError) as e:
            logger.warning("Failed to parse %s: %s", profiles_ini, e)
            return []

        dirs: list[Path] = []
        for section in parser.sections():
            if not section.lower().startswith("profile"):
                continue
            path_value = parser.get(section, "Path", fallback=None)
            if not path_value:
                continue
            is_relative = parser.get(section, "IsRelative", fallback="1").strip() == "1"
            if is_relative:
                profile_dir = profiles_root / path_value
            else:
                profile_dir = Path(path_value)
            dirs.append(profile_dir)

        return dirs

    def _scan_firefox_profile(
        self, profile_dir: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        if not profile_dir.exists():
            logger.debug("Firefox profile dir missing: %s", profile_dir)
            return

        logger.debug("Scanning Firefox profile: %s", profile_dir)

        self._scan_firefox_webappsstore(profile_dir, result, show_secrets)
        self._scan_firefox_cookies(profile_dir, result, show_secrets)

    def _scan_firefox_webappsstore(
        self, profile_dir: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        db_path = profile_dir / "webappsstore.sqlite"
        if not db_path.exists():
            logger.debug("webappsstore.sqlite not found in %s", profile_dir)
            return

        perms = get_file_permissions(db_path)
        owner = get_file_owner(db_path)
        mtime = get_file_mtime(db_path)

        # Build a WHERE clause against AI_DOMAINS. Firefox originKey is
        # reversed-domain (e.g. "moc.ia-edualc.:https:443") so we match on
        # the reversed form.
        where_clauses = []
        params: list[str] = []
        for domain in AI_DOMAINS:
            reversed_domain = domain[::-1]
            where_clauses.append("originKey LIKE ?")
            params.append(f"%{reversed_domain}%")
        where_sql = " OR ".join(where_clauses)

        try:
            uri = f"file:{db_path}?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=1)
        except sqlite3.OperationalError as e:
            logger.debug("Could not open %s read-only: %s", db_path, e)
            result.errors.append(f"Firefox DB locked (browser running?): {db_path}")
            return

        try:
            cur = conn.cursor()
            try:
                cur.execute(
                    f"SELECT originKey, key, value FROM webappsstore2 WHERE {where_sql}",
                    params,
                )
                rows = cur.fetchall()
            except sqlite3.OperationalError as e:
                # webappsstore2 may not exist in very old/new profiles
                logger.debug("Query failed on %s: %s", db_path, e)
                result.errors.append(f"Firefox webappsstore2 query failed on {db_path}: {e}")
                return
        finally:
            try:
                conn.close()
            except sqlite3.Error:
                pass

        if not rows:
            logger.debug("No AI-domain localStorage rows in %s", db_path)
            return

        for origin_key, key, value in rows:
            try:
                domain = self._domain_from_origin_key(origin_key)
            except Exception:
                domain = str(origin_key)

            key_str = str(key) if key is not None else ""
            value_str = "" if value is None else str(value)

            notes: list[str] = [
                f"originKey: {origin_key}",
                f"localStorage key: {key_str[:120]}",
            ]
            if mtime:
                notes.append(f"Database last modified: {describe_staleness(mtime)}")
            if self._looks_session_like(key_str):
                notes.append("Key name suggests a session/auth token")

            preview = mask_value(value_str, show_full=show_secrets) if value_str else "(empty)"

            result.findings.append(CredentialFinding(
                tool_name=f"Firefox: {domain}",
                credential_type="browser_localstorage",
                storage_type=StorageType.ENCRYPTED_DB,
                location=str(db_path),
                exists=True,
                risk_level=RiskLevel.MEDIUM,
                value_preview=preview,
                raw_value=value_str if show_secrets else None,
                file_permissions=perms,
                file_owner=owner,
                file_modified=mtime,
                remediation=(
                    "Ensure browser profile directory has restricted permissions "
                    "(chmod 700). Clear site data to revoke local sessions."
                ),
                remediation_hint=hint_chmod("700", str(profile_dir)),
                notes=notes,
            ))

    def _scan_firefox_cookies(
        self, profile_dir: Path, result: ScanResult, show_secrets: bool
    ) -> None:
        db_path = profile_dir / "cookies.sqlite"
        if not db_path.exists():
            logger.debug("cookies.sqlite not found in %s", profile_dir)
            return

        perms = get_file_permissions(db_path)
        owner = get_file_owner(db_path)
        mtime = get_file_mtime(db_path)

        where_clauses = []
        params: list[str] = []
        for domain in AI_DOMAINS:
            where_clauses.append("host LIKE ?")
            params.append(f"%{domain}%")
        where_sql = " OR ".join(where_clauses)

        try:
            uri = f"file:{db_path}?mode=ro"
            conn = sqlite3.connect(uri, uri=True, timeout=1)
        except sqlite3.OperationalError as e:
            logger.debug("Could not open cookies DB read-only: %s (%s)", db_path, e)
            result.errors.append(f"Firefox cookies DB locked (browser running?): {db_path}")
            return

        try:
            cur = conn.cursor()
            try:
                cur.execute(
                    f"SELECT host, name, value FROM moz_cookies WHERE {where_sql}",
                    params,
                )
                rows = cur.fetchall()
            except sqlite3.OperationalError as e:
                logger.debug("moz_cookies query failed on %s: %s", db_path, e)
                result.errors.append(f"Firefox moz_cookies query failed on {db_path}: {e}")
                return
        finally:
            try:
                conn.close()
            except sqlite3.Error:
                pass

        for host, name, value in rows:
            name_str = str(name) if name is not None else ""
            if not self._looks_session_like(name_str):
                continue

            value_str = "" if value is None else str(value)
            host_str = str(host) if host is not None else ""

            notes: list[str] = [
                f"Cookie host: {host_str}",
                f"Cookie name: {name_str}",
            ]
            if mtime:
                notes.append(f"Database last modified: {describe_staleness(mtime)}")

            preview = mask_value(value_str, show_full=show_secrets) if value_str else "(empty)"

            result.findings.append(CredentialFinding(
                tool_name=f"Firefox cookie: {host_str.lstrip('.')}",
                credential_type="browser_cookie",
                storage_type=StorageType.ENCRYPTED_DB,
                location=str(db_path),
                exists=True,
                risk_level=RiskLevel.MEDIUM,
                value_preview=preview,
                raw_value=value_str if show_secrets else None,
                file_permissions=perms,
                file_owner=owner,
                file_modified=mtime,
                remediation=(
                    "Ensure browser profile directory has restricted permissions "
                    "(chmod 700). Clear site cookies to revoke this session."
                ),
                remediation_hint=hint_chmod("700", str(profile_dir)),
                notes=notes,
            ))

    @staticmethod
    def _domain_from_origin_key(origin_key: Optional[str]) -> str:
        """Parse a Firefox originKey like 'moc.ia-edualc.:https:443' into 'claude.ai'."""
        if not origin_key:
            return "unknown"
        # The format is "<reversed-domain>:<scheme>:<port>"
        parts = str(origin_key).split(":")
        reversed_domain = parts[0] if parts else str(origin_key)
        # Trim a trailing dot left by the reversed form (e.g. "moc.ia-edualc.")
        reversed_domain = reversed_domain.rstrip(".")
        return reversed_domain[::-1] if reversed_domain else "unknown"

    @staticmethod
    def _looks_session_like(name: str) -> bool:
        lowered = name.lower()
        return any(keyword in lowered for keyword in SESSION_COOKIE_KEYWORDS)

    # ------------------------------------------------------------------ #
    # Chromium stubs
    # ------------------------------------------------------------------ #

    def _get_chromium_local_storage_dirs(
        self, plat: Platform
    ) -> list[tuple[str, Path]]:
        """Return a list of (browser_name, Local Storage directory) tuples."""
        entries: list[tuple[str, Path]] = []
        home = get_home()

        def _linux_entries() -> list[tuple[str, Path]]:
            return [
                ("Google Chrome", home / ".config" / "google-chrome" / "Default" / "Local Storage"),
                ("Brave", home / ".config" / "BraveSoftware" / "Brave-Browser" / "Default" / "Local Storage"),
                ("Chromium", home / ".config" / "chromium" / "Default" / "Local Storage"),
                ("Microsoft Edge", home / ".config" / "microsoft-edge" / "Default" / "Local Storage"),
            ]

        def _macos_entries() -> list[tuple[str, Path]]:
            return [
                (
                    "Google Chrome",
                    home / "Library" / "Application Support" / "Google" / "Chrome" / "Default" / "Local Storage",
                ),
                (
                    "Brave",
                    home / "Library" / "Application Support" / "BraveSoftware" / "Brave-Browser" / "Default" / "Local Storage",
                ),
                (
                    "Microsoft Edge",
                    home / "Library" / "Application Support" / "Microsoft Edge" / "Default" / "Local Storage",
                ),
            ]

        def _windows_entries(localappdata: Path) -> list[tuple[str, Path]]:
            return [
                ("Google Chrome", localappdata / "Google" / "Chrome" / "User Data" / "Default" / "Local Storage"),
                ("Microsoft Edge", localappdata / "Microsoft" / "Edge" / "User Data" / "Default" / "Local Storage"),
                ("Brave", localappdata / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Local Storage"),
            ]

        if plat == Platform.LINUX:
            entries.extend(_linux_entries())
        elif plat == Platform.MACOS:
            entries.extend(_macos_entries())
        elif plat == Platform.WINDOWS:
            localappdata = get_localappdata()
            if localappdata:
                entries.extend(_windows_entries(localappdata))
        elif plat == Platform.WSL:
            entries.extend(_linux_entries())
            localappdata = get_localappdata()
            if localappdata:
                entries.extend(_windows_entries(localappdata))

        return entries

    def _record_chromium_stub(
        self, browser_name: str, local_storage_dir: Path, result: ScanResult
    ) -> None:
        if not local_storage_dir.exists() or not local_storage_dir.is_dir():
            return

        # Look for actual content; LevelDB data lives in a "leveldb" subdir.
        try:
            has_contents = any(local_storage_dir.iterdir())
        except OSError:
            has_contents = False
        if not has_contents:
            return

        mtime = get_file_mtime(local_storage_dir)
        notes = [
            "Chromium LevelDB requires optional dependency to parse",
            "AI session tokens may exist in this storage",
        ]
        if mtime:
            notes.append(f"Directory last modified: {describe_staleness(mtime)}")

        result.findings.append(CredentialFinding(
            tool_name=f"{browser_name} (not scanned)",
            credential_type="browser_localstorage",
            storage_type=StorageType.ENCRYPTED_DB,
            location=str(local_storage_dir),
            exists=True,
            risk_level=RiskLevel.INFO,
            file_modified=mtime,
            remediation=(
                "Review browser storage manually or use dedicated Chromium "
                "LevelDB tools."
            ),
            remediation_hint=hint_manual(
                "Review browser storage manually or use dedicated Chromium LevelDB tools."
            ),
            notes=notes,
        ))
