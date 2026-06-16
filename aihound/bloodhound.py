"""BloodHound CE API client for AIHound query import.

Handles authentication (password or token) and importing saved queries
from extension/queries.json into a BloodHound CE instance.

Note: Token auth uses base64-encoded token_id:token_key as Bearer token.
This matches the existing register_ai_nodes.py behavior but may not work
with all BloodHound CE versions that require HMAC-SHA-256 signing.
Password auth is the recommended approach.
"""

from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.request
from pathlib import Path


# Default paths — support both normal install and PyInstaller bundle
import sys as _sys

if getattr(_sys, "frozen", False):
    # PyInstaller bundles extension/ into _MEIPASS
    _EXTENSION_DIR = Path(_sys._MEIPASS) / "extension"
else:
    _EXTENSION_DIR = Path(__file__).resolve().parent.parent / "extension"
_QUERIES_PATH = _EXTENSION_DIR / "queries.json"
_SCHEMA_PATH = _EXTENSION_DIR / "schema.json"


def load_schema(filepath: str | None = None) -> dict:
    """Load the OpenGraph extension schema.

    Args:
        filepath: Path to schema JSON. Defaults to extension/schema.json.

    Returns:
        Schema dict ready to PUT to /api/v2/extensions.
    """
    path = Path(filepath) if filepath else _SCHEMA_PATH
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_queries(filepath: str | None = None) -> list[dict]:
    """Load queries from a JSON file in SpecterOps Query Library format.

    Args:
        filepath: Path to queries JSON. Defaults to extension/queries.json.

    Returns:
        List of query dicts, each with at least 'name' and 'query' keys.
    """
    path = Path(filepath) if filepath else _QUERIES_PATH
    with open(path, encoding="utf-8") as f:
        return json.load(f)


class BloodHoundClient:
    """Simple HTTP client for BloodHound CE saved-query import."""

    def __init__(self, server: str, verify_ssl: bool = True) -> None:
        self.server = server.rstrip("/")
        self.token: str | None = None
        self.ssl_ctx = ssl.create_default_context()
        if not verify_ssl:
            self.ssl_ctx.check_hostname = False
            self.ssl_ctx.verify_mode = ssl.CERT_NONE

    def _request(self, method: str, path: str,
                 data: dict | None = None) -> dict:
        """Make an HTTP request to the BloodHound CE API."""
        url = f"{self.server}{path}"
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(
            url, data=body, headers=headers, method=method
        )

        try:
            with urllib.request.urlopen(req, context=self.ssl_ctx) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            error_body = e.read().decode() if e.readable() else ""
            raise RuntimeError(
                f"BloodHound API error: HTTP {e.code} {e.reason}: {error_body}"
            ) from e

    def _request_no_body(self, method: str, path: str,
                         data: dict | None = None) -> None:
        """Make an HTTP request that may return an empty body."""
        url = f"{self.server}{path}"
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(
            url, data=body, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req, context=self.ssl_ctx) as resp:
                resp.read()
        except urllib.error.HTTPError as e:
            error_body = e.read().decode() if e.readable() else ""
            raise RuntimeError(
                f"BloodHound API error: HTTP {e.code} {e.reason}: {error_body}"
            ) from e

    def login_password(self, username: str, password: str) -> None:
        """Authenticate with username and password."""
        resp = self._request("POST", "/api/v2/login", {
            "login_method": "secret",
            "secret": password,
            "username": username,
        })
        self.token = (
            resp.get("session_token")
            or resp.get("data", {}).get("session_token")
        )
        if not self.token:
            raise RuntimeError(
                f"Login failed — no session_token in response: {resp}"
            )

    def login_token(self, token_id: str, token_key: str) -> None:
        """Authenticate with API token ID and key."""
        credentials = base64.b64encode(
            f"{token_id}:{token_key}".encode()
        ).decode()
        self.token = credentials
        try:
            self._request("GET", "/api/v2/self")
        except RuntimeError:
            raise RuntimeError(
                "Token authentication failed — check token ID and key"
            )

    def register_schema(self, schema: dict) -> None:
        """Register the AIHound OpenGraph extension schema.

        Uses PUT /api/v2/extensions to register node kinds with icons,
        colors, relationship kinds, and environments.
        """
        self._request_no_body("PUT", "/api/v2/extensions", schema)

    def import_queries(
        self, queries: list[dict]
    ) -> tuple[int, int]:
        """Import saved queries, skipping any that already exist by name.

        Args:
            queries: List of query dicts with 'name' and 'query' keys.

        Returns:
            Tuple of (created_count, skipped_count).
        """
        existing = self._request("GET", "/api/v2/saved-queries")
        existing_names = {
            q["name"] for q in existing.get("data", [])
        }

        created = 0
        skipped = 0
        for q in queries:
            if q["name"] in existing_names:
                skipped += 1
                continue
            self._request("POST", "/api/v2/saved-queries", {
                "name": q["name"],
                "query": q["query"],
            })
            created += 1

        return created, skipped
