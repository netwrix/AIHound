#!/usr/bin/env python3
"""Register AIHound custom node kinds and icons in BloodHound CE.

Run once per BloodHound CE instance to enable custom visualization
of AI credential nodes with distinct icons and colors.

Usage:
    # Username/password auth:
    python3 register_ai_nodes.py -s http://localhost:8080 -u admin -p <password>

    # Token auth:
    python3 register_ai_nodes.py -s http://localhost:8080 --token-id <uuid> --token-key <key>

    # Reset existing custom kinds first:
    python3 register_ai_nodes.py -s http://localhost:8080 -u admin -p <password> --reset
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
import ssl


# Custom node kinds with Font Awesome icon names and colors.
# Icon names are bare FA free-solid names (no "fa-" prefix).
# BloodHound CE requires: {"type": "font-awesome", "name": "<icon>", "color": "#RRGGBB"}
AI_NODE_KINDS: dict[str, dict] = {
    "AICredential": {
        "icon": "key",
        "color": "#e74c3c",       # Red
        "description": "AI API key, OAuth token, or session credential",
    },
    "AIService": {
        "icon": "cloud",
        "color": "#3498db",       # Blue
        "description": "AI platform or service (OpenAI, Anthropic, AWS, etc.)",
    },
    "MCPServer": {
        "icon": "plug",
        "color": "#9b59b6",       # Purple
        "description": "Model Context Protocol server instance",
    },
    "ConfigFile": {
        "icon": "file-lines",
        "color": "#e67e22",       # Orange
        "description": "Configuration file containing AI credentials",
    },
    "EnvVariable": {
        "icon": "terminal",
        "color": "#27ae60",       # Green
        "description": "Environment variable holding a secret",
    },
    "AITool": {
        "icon": "wrench",
        "color": "#1abc9c",       # Teal
        "description": "AI coding assistant or tool (Claude Code, Cursor, etc.)",
    },
    "NetworkEndpoint": {
        "icon": "globe",
        "color": "#c0392b",       # Dark Red
        "description": "Network-exposed AI service endpoint",
    },
    "DataStore": {
        "icon": "database",
        "color": "#f39c12",       # Gold
        "description": "Accessible data (conversation history, models, training data)",
    },
    "CredentialStore": {
        "icon": "lock",
        "color": "#95a5a6",       # Gray
        "description": "OS credential store (macOS Keychain, Windows Credential Manager)",
    },
    "ShellHistory": {
        "icon": "scroll",
        "color": "#f1c40f",       # Yellow
        "description": "Shell history file containing leaked credentials",
    },
    "DockerConfig": {
        "icon": "cube",
        "color": "#2980b9",       # Docker Blue
        "description": "Docker daemon configuration with registry auth",
    },
    "BrowserSession": {
        "icon": "window-maximize",
        "color": "#00bcd4",       # Cyan
        "description": "Browser cookie or localStorage session for AI service",
    },
    "GitCredential": {
        "icon": "code-branch",
        "color": "#d35400",       # Dark Orange
        "description": "Git credential helper or .git-credentials entry",
    },
    "JupyterInstance": {
        "icon": "book",
        "color": "#e67e22",       # Orange
        "description": "Jupyter notebook server instance",
    },
}


class BloodHoundClient:
    """Simple HTTP client for BloodHound CE API."""

    def __init__(self, server: str, verify_ssl: bool = True) -> None:
        self.server = server.rstrip("/")
        self.token: str | None = None
        # Create SSL context
        if verify_ssl:
            self.ssl_ctx = ssl.create_default_context()
        else:
            self.ssl_ctx = ssl.create_default_context()
            self.ssl_ctx.check_hostname = False
            self.ssl_ctx.verify_mode = ssl.CERT_NONE

    def _request(self, method: str, path: str, data: dict | None = None) -> dict:
        """Make an HTTP request to the BloodHound CE API."""
        url = f"{self.server}{path}"
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=body, headers=headers, method=method)

        try:
            with urllib.request.urlopen(req, context=self.ssl_ctx) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            error_body = e.read().decode() if e.readable() else ""
            print(f"HTTP {e.code} {e.reason}: {error_body}", file=sys.stderr)
            raise

    def login_password(self, username: str, password: str) -> None:
        """Authenticate with username and password."""
        resp = self._request("POST", "/api/v2/login", {
            "login_method": "secret",
            "secret": password,
            "username": username,
        })
        self.token = resp.get("session_token") or resp.get("data", {}).get("session_token")
        if not self.token:
            raise RuntimeError(f"Login failed — no session_token in response: {resp}")
        print(f"Authenticated as {username}")

    def login_token(self, token_id: str, token_key: str) -> None:
        """Authenticate with API token ID and key."""
        # Token auth uses HMAC — for simplicity, set as Bearer token directly
        # BloodHound CE also supports token_id:token_key as basic auth
        import base64
        credentials = base64.b64encode(f"{token_id}:{token_key}".encode()).decode()
        self.token = credentials
        # Verify it works
        try:
            self._request("GET", "/api/v2/self")
            print("Authenticated with API token")
        except Exception:
            raise RuntimeError("Token authentication failed — check token ID and key")

    def reset_custom_kinds(self) -> None:
        """Delete all existing custom node kinds."""
        try:
            self._request("DELETE", "/api/v2/custom-nodes")
            print("Cleared existing custom node kinds")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                print("No existing custom kinds to clear")
            else:
                raise

    def register_kinds(self, kinds: dict[str, dict]) -> None:
        """Register custom node kinds with icons."""
        payload = {"custom_types": {}}
        for kind_name, kind_def in kinds.items():
            payload["custom_types"][kind_name] = {
                "icon": {
                    "type": "font-awesome",
                    "name": kind_def["icon"],
                    "color": kind_def["color"],
                },
            }

        self._request("POST", "/api/v2/custom-nodes", payload)
        print(f"Registered {len(kinds)} custom node kinds:")
        for name, defn in kinds.items():
            print(f"  {defn['icon']:>20}  {name:<20}  {defn['description']}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Register AIHound custom node kinds in BloodHound CE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-s", "--server", required=True,
                        help="BloodHound CE server URL (e.g., http://localhost:8080)")
    parser.add_argument("-u", "--username", help="BloodHound username")
    parser.add_argument("-p", "--password", help="BloodHound password")
    parser.add_argument("--token-id", help="API token ID (UUID)")
    parser.add_argument("--token-key", help="API token key (base64)")
    parser.add_argument("--reset", action="store_true",
                        help="Delete all existing custom node kinds before registering")
    parser.add_argument("--no-verify-ssl", action="store_true",
                        help="Disable SSL certificate verification")
    parser.add_argument("--list", action="store_true",
                        help="List custom node kinds that would be registered and exit")

    args = parser.parse_args()

    # --list: just print the kinds and exit
    if args.list:
        print("AIHound custom node kinds for BloodHound CE:\n")
        for name, defn in AI_NODE_KINDS.items():
            print(f"  {defn['icon']:>20}  {defn['color']}  {name:<20}  {defn['description']}")
        return 0

    # Validate auth args
    has_password = args.username and args.password
    has_token = args.token_id and args.token_key
    if not has_password and not has_token:
        parser.error("Provide either --username/--password or --token-id/--token-key")

    client = BloodHoundClient(args.server, verify_ssl=not args.no_verify_ssl)

    try:
        # Authenticate
        if has_password:
            client.login_password(args.username, args.password)
        else:
            client.login_token(args.token_id, args.token_key)

        # Reset if requested
        if args.reset:
            client.reset_custom_kinds()

        # Register kinds
        client.register_kinds(AI_NODE_KINDS)
        print("\nDone! You can now import AIHound OpenGraph JSON files into BloodHound CE.")

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
