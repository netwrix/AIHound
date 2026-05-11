#!/usr/bin/env python3
"""Register AIHound custom node kinds, icons, and saved queries in BloodHound CE.

Run once per BloodHound CE instance to enable custom visualization
of AI credential nodes with distinct icons and colors.

Usage:
    # Username/password auth (registers node kinds + saved queries):
    python3 register_ai_nodes.py -s http://localhost:8080 -u admin -p <password>

    # Token auth:
    python3 register_ai_nodes.py -s http://localhost:8080 --token-id <uuid> --token-key <key>

    # Reset (delete + re-register node kinds and saved queries):
    python3 register_ai_nodes.py -s http://localhost:8080 -u admin -p <password> --reset

    # Unregister all custom kinds and saved queries:
    python3 register_ai_nodes.py -s http://localhost:8080 -u admin -p <password> --unregister

    # Skip saved queries:
    python3 register_ai_nodes.py -s http://localhost:8080 -u admin -p <password> --no-queries
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
import ssl
from pathlib import Path


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

    def _request_no_body(self, method: str, path: str,
                         data: dict | None = None) -> None:
        """Make an HTTP request that may return an empty body (e.g. DELETE, PUT)."""
        url = f"{self.server}{path}"
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        with urllib.request.urlopen(req, context=self.ssl_ctx) as resp:
            resp.read()  # drain response

    def list_custom_kinds(self) -> list[str]:
        """Return the names of all registered custom node kinds."""
        resp = self._request("GET", "/api/v2/custom-nodes")
        entries = resp.get("data", [])
        return [e["kindName"] for e in entries]

    def delete_custom_kind(self, kind_name: str) -> None:
        """Delete a single custom node kind by name."""
        try:
            self._request_no_body("DELETE", f"/api/v2/custom-nodes/{kind_name}")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                pass  # already gone
            else:
                raise

    def reset_custom_kinds(self) -> None:
        """Delete all registered custom node kinds one-by-one.

        BHCE 9.x does not support bulk DELETE on /api/v2/custom-nodes.
        Instead we list all kinds and delete each via
        DELETE /api/v2/custom-nodes/{kind_name}.
        """
        existing = self.list_custom_kinds()
        if not existing:
            print("No custom node kinds to remove")
            return
        for name in existing:
            self.delete_custom_kind(name)
        print(f"Removed {len(existing)} custom node kinds: {', '.join(existing)}")

    def register_kinds(self, kinds: dict[str, dict]) -> None:
        """Register custom node kinds with icons.

        Uses POST for initial creation. If kinds already exist (HTTP 409),
        treats as success — re-run with --reset first to force re-registration.
        """
        payload = {"custom_types": {}}
        for kind_name, kind_def in kinds.items():
            payload["custom_types"][kind_name] = {
                "icon": {
                    "type": "font-awesome",
                    "name": kind_def["icon"],
                    "color": kind_def["color"],
                },
            }

        try:
            self._request("POST", "/api/v2/custom-nodes", payload)
        except urllib.error.HTTPError as e:
            if e.code == 409:
                print("Custom node kinds already registered (use --reset to re-register)")
            else:
                raise
        print(f"Registered {len(kinds)} custom node kinds:")
        for name, defn in kinds.items():
            print(f"  {defn['icon']:>20}  {name:<20}  {defn['description']}")

    # ----- OpenGraph Extension (v9.1.0+) -----

    def _has_extension_support(self) -> bool:
        """Check if the server supports the OpenGraph extensions API (v9.1.0+)."""
        try:
            # Enable the feature flag if possible
            resp = self._request("GET", "/api/v2/features")
            for feat in resp.get("data", []):
                if feat.get("key") == "opengraph_extension_management":
                    if not feat.get("enabled") and feat.get("user_updatable"):
                        try:
                            self._request("PUT", f"/api/v2/features/{feat['id']}/toggle")
                        except Exception:
                            # Toggle endpoint may return non-JSON — that's OK
                            pass
                        print("Enabled opengraph_extension_management feature flag")
                    elif not feat.get("enabled"):
                        return False
                    return True
        except Exception:
            pass
        return False

    def register_extension(self, kinds: dict[str, dict], version: str = "v3.2.1") -> bool:
        """Register AIHound as an OpenGraph extension with is_display_kind.

        This is the v9.1.0+ registration method that enables proper icon
        resolution via the extension schema system.

        Returns True if successful, False if not supported.
        """
        if not self._has_extension_support():
            return False

        prefix = "AIHound_"

        node_kinds = [
            {"name": f"{prefix}Environment", "display_name": "AIHound Environment",
             "description": "AIHound scan environment", "is_display_kind": False},
        ]
        for kind_name, kind_def in kinds.items():
            node_kinds.append({
                "name": f"{prefix}{kind_name}",
                "display_name": kind_def.get("description", kind_name)[:60],
                "description": kind_def.get("description", ""),
                "is_display_kind": True,
                "icon": kind_def["icon"],
                "color": kind_def["color"],
            })

        # Collect all edge kinds used by the graph builder
        edge_kinds = [
            "Authenticates", "StoredIn", "ContainsCredential", "ReadsFrom",
            "GrantsAccessTo", "ExposesService", "UsesMCPServer",
            "RequiresCredential", "ConfiguredBy", "InheritsEnv",
            "BrowserAuthTo", "DockerRegistryAuth", "GitAuthTo", "SameSecret",
        ]

        principal_kinds = [f"{prefix}{k}" for k in kinds]

        payload = {
            "schema": {
                "name": "AIHound",
                "display_name": "AIHound",
                "version": version,
                "namespace": "AIHound",
            },
            "node_kinds": node_kinds,
            "relationship_kinds": [
                {"name": f"{prefix}{ek}", "description": ek, "is_traversable": True}
                for ek in edge_kinds
            ],
            "environments": [{
                "environment_kind": f"{prefix}Environment",
                "source_kind": "AIHound",
                "principal_kinds": principal_kinds,
            }],
        }

        try:
            self._request_no_body("PUT", "/api/v2/extensions", payload)
            print(f"Registered AIHound OpenGraph extension (v9.1.0+ mode):")
            for nk in node_kinds:
                if nk.get("is_display_kind"):
                    print(f"  {nk.get('icon', ''):>20}  {nk['name']:<30}  {nk['display_name']}")
            return True
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return False  # endpoint not available
            raise

    # ----- Saved Queries -----

    def list_saved_queries(self) -> list[dict]:
        """Return all saved queries."""
        resp = self._request("GET", "/api/v2/saved-queries")
        return resp.get("data", [])

    def create_saved_query(self, name: str, query: str) -> None:
        """Create a single saved query."""
        self._request("POST", "/api/v2/saved-queries", {
            "name": name,
            "query": query,
        })

    def delete_saved_query(self, query_id: int) -> None:
        """Delete a saved query by ID."""
        try:
            self._request_no_body("DELETE", f"/api/v2/saved-queries/{query_id}")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                pass
            else:
                raise

    def reset_saved_queries(self) -> None:
        """Delete all AIHound saved queries (those prefixed with 'AIHound')."""
        existing = self.list_saved_queries()
        removed = 0
        for q in existing:
            if q.get("name", "").startswith("AIHound"):
                self.delete_saved_query(q["id"])
                removed += 1
        if removed:
            print(f"Removed {removed} AIHound saved queries")
        else:
            print("No AIHound saved queries to remove")

    def register_saved_queries(self, queries: list[tuple[str, str]]) -> None:
        """Register saved queries, skipping any that already exist by name."""
        existing_names = {q["name"] for q in self.list_saved_queries()}
        created = 0
        skipped = 0
        for name, query in queries:
            if name in existing_names:
                skipped += 1
                continue
            self.create_saved_query(name, query)
            created += 1
        print(f"Saved queries: {created} created, {skipped} already existed")


def parse_cypher_file(filepath: str) -> list[tuple[str, str]]:
    """Parse a .cy file into (name, query) pairs.

    Format: lines starting with // before a query block are treated as
    comments. The last non-section comment before a query becomes its name.
    Section headers (// ---...) and their titles are used to group queries.
    """
    queries: list[tuple[str, str]] = []
    lines = Path(filepath).read_text(encoding="utf-8").splitlines()

    section = ""
    comment = ""
    query_lines: list[str] = []

    def _flush() -> None:
        nonlocal comment, query_lines
        if query_lines:
            query = "\n".join(query_lines).strip()
            if query:
                name = f"AIHound - {section} - {comment}" if comment else f"AIHound - {section}"
                # Deduplicate names by appending a suffix if needed
                base_name = name
                counter = 2
                existing_names = {n for n, _ in queries}
                while name in existing_names:
                    name = f"{base_name} ({counter})"
                    counter += 1
                queries.append((name, query))
        query_lines.clear()
        comment = ""

    for line in lines:
        stripped = line.strip()

        # Section header: // ----...
        if stripped.startswith("// ---"):
            _flush()
            continue

        # Section title: // N. TITLE
        m = re.match(r"^//\s*\d+\.\s+(.+)", stripped)
        if m:
            _flush()
            section = m.group(1).split("—")[0].split("–")[0].strip()
            continue

        # Top-level header or instruction comments — skip
        if stripped.startswith("// ===") or stripped.startswith("// Import") or stripped.startswith("// IMPORTANT"):
            _flush()
            continue

        # Table section header
        if stripped.startswith("// TABLE QUERIES") or stripped.startswith("// ="):
            _flush()
            section = "Table Queries"
            continue

        # Regular comment before a query → candidate name
        if stripped.startswith("//"):
            if not query_lines:
                # Use the comment text (strip leading //)
                c = stripped.lstrip("/").strip()
                if c and not c.startswith("NOTE"):
                    comment = c
            continue

        # Empty line
        if not stripped:
            _flush()
            continue

        # Cypher line
        query_lines.append(stripped)

    _flush()
    return queries


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
    parser.add_argument("--unregister", action="store_true",
                        help="Delete all AIHound custom node kinds and saved queries, then exit")
    parser.add_argument("--no-queries", action="store_true",
                        help="Skip registering saved Cypher queries")
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

        # Unregister only
        if args.unregister:
            client.reset_custom_kinds()
            client.reset_saved_queries()
            print("\nDone! All AIHound custom node kinds and saved queries have been removed.")
            return 0

        # Reset if requested (delete then re-create)
        if args.reset:
            client.reset_custom_kinds()
            if not args.no_queries:
                client.reset_saved_queries()

        # Register kinds via v9.1.0+ extension API (is_display_kind).
        # Also register custom-nodes with prefixed names as a fallback
        # for pre-9.1.0 icon resolution.
        client.register_extension(AI_NODE_KINDS)

        # Register prefixed custom-nodes for pre-9.1.0 frontend icon matching
        prefixed_kinds = {
            f"AIHound_{name}": defn for name, defn in AI_NODE_KINDS.items()
        }
        client.register_kinds(prefixed_kinds)

        # Register saved queries from cypher_queries.cy
        if not args.no_queries:
            cy_file = Path(__file__).resolve().parent / "cypher_queries.cy"
            if cy_file.exists():
                queries = parse_cypher_file(str(cy_file))
                client.register_saved_queries(queries)
            else:
                print(f"Skipping saved queries — {cy_file} not found")

        print("\nDone! You can now import AIHound OpenGraph JSON files into BloodHound CE.")

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
