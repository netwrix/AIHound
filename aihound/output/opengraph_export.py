"""Convert AIHound scan results to BloodHound CE OpenGraph JSON.

Generates a JSON file compatible with BloodHound CE v8.0+ OpenGraph ingest.
Custom AI node kinds are defined with distinct icons for visualization.

Usage:
    from aihound.output.opengraph_export import export_opengraph
    export_opengraph(results, filepath="output.json")
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, TextIO

from aihound.core.scanner import ScanResult, CredentialFinding, StorageType, RiskLevel
from aihound.core.redactor import KNOWN_PREFIXES


# ---------------------------------------------------------------------------
# Service inference mappings
# ---------------------------------------------------------------------------

# tool_name -> service name (for tools that are clearly tied to one service)
TOOL_TO_SERVICE: dict[str, str] = {
    "Claude Code CLI": "Anthropic",
    "Claude Desktop": "Anthropic",
    "Claude Sessions": "Anthropic",
    "OpenAI/Codex CLI": "OpenAI",
    "ChatGPT Desktop": "OpenAI",
    "GitHub Copilot": "GitHub Copilot",
    "Gemini CLI / GCloud": "Google AI",
    "Hugging Face CLI": "Hugging Face",
    "Amazon Q / AWS": "AWS",
    "Ollama": "Ollama",
    "LM Studio": "LM Studio",
    "Jupyter": "Jupyter",
}

# credential_type patterns -> service name
CRED_TYPE_TO_SERVICE: dict[str, str] = {
    "oauth_access_token": "Anthropic",
    "oauth_refresh_token": "Anthropic",
    "hf_token": "Hugging Face",
    "sso_access_token": "AWS",
    "network_exposure": None,  # handled separately
    "active_claude_session": "Anthropic",
    "active_claude_process": "Anthropic",
    "claude_session_file": "Anthropic",
    "live_oauth_session": "Anthropic",
    "tmux_claude_session": "Anthropic",
    "screen_claude_session": "Anthropic",
    "claude_mcp_server_exposed": "Anthropic",
    "gateway_auth_token": None,
}

# value_preview prefix -> service name (ordered longest-first for matching)
PREFIX_TO_SERVICE: dict[str, str] = {
    "sk-ant-ort": "Anthropic",
    "sk-ant-oat": "Anthropic",
    "sk-ant-": "Anthropic",
    "ghp_": "GitHub",
    "gho_": "GitHub",
    "ghu_": "GitHub",
    "ghs_": "GitHub",
    "github_pat_": "GitHub",
    "xoxb-": "Slack",
    "xoxp-": "Slack",
    "xoxa-": "Slack",
    "AKIA": "AWS",
    "AIza": "Google AI",
    "ya29.": "Google AI",
    "sk-": "OpenAI",
    "hf_": "Hugging Face",
}

# env var name patterns -> service name
ENV_VAR_TO_SERVICE: dict[str, str] = {
    "ANTHROPIC_API_KEY": "Anthropic",
    "CLAUDE_API_KEY": "Anthropic",
    "OPENAI_API_KEY": "OpenAI",
    "OPENAI_ORG_ID": "OpenAI",
    "GITHUB_TOKEN": "GitHub",
    "GITHUB_COPILOT_TOKEN": "GitHub Copilot",
    "GH_TOKEN": "GitHub",
    "HUGGING_FACE_HUB_TOKEN": "Hugging Face",
    "HF_TOKEN": "Hugging Face",
    "HUGGINGFACE_TOKEN": "Hugging Face",
    "AWS_ACCESS_KEY_ID": "AWS",
    "AWS_SECRET_ACCESS_KEY": "AWS",
    "AWS_SESSION_TOKEN": "AWS",
    "GOOGLE_API_KEY": "Google AI",
    "GEMINI_API_KEY": "Google AI",
    "GOOGLE_APPLICATION_CREDENTIALS": "Google AI",
    "REPLICATE_API_TOKEN": "Replicate",
    "TOGETHER_API_KEY": "Together AI",
    "GROQ_API_KEY": "Groq",
    "OLLAMA_HOST": "Ollama",
    "COHERE_API_KEY": "Cohere",
    "MISTRAL_API_KEY": "Mistral",
    "DEEPSEEK_API_KEY": "DeepSeek",
    "PERPLEXITY_API_KEY": "Perplexity",
    "FIREWORKS_API_KEY": "Fireworks AI",
    "VOYAGE_API_KEY": "Voyage AI",
    "PINECONE_API_KEY": "Pinecone",
    "WEAVIATE_API_KEY": "Weaviate",
    "SLACK_BOT_TOKEN": "Slack",
    "SLACK_TOKEN": "Slack",
}

# service -> data stores it grants access to
SERVICE_DATA_STORES: dict[str, list[dict[str, str]]] = {
    "Anthropic": [
        {"type": "conversation_history", "name": "Anthropic Conversation History", "sensitivity": "high"},
        {"type": "billing", "name": "Anthropic Billing & Usage", "sensitivity": "medium"},
    ],
    "OpenAI": [
        {"type": "conversation_history", "name": "OpenAI Conversation History", "sensitivity": "high"},
        {"type": "fine_tuning_data", "name": "OpenAI Fine-Tuning Data", "sensitivity": "high"},
        {"type": "file_storage", "name": "OpenAI File Storage", "sensitivity": "high"},
        {"type": "billing", "name": "OpenAI Billing & Usage", "sensitivity": "medium"},
    ],
    "Hugging Face": [
        {"type": "model_repos", "name": "HuggingFace Model Repositories", "sensitivity": "high"},
        {"type": "datasets", "name": "HuggingFace Datasets", "sensitivity": "high"},
        {"type": "tokens", "name": "HuggingFace Access Tokens", "sensitivity": "medium"},
    ],
    "AWS": [
        {"type": "bedrock_models", "name": "AWS Bedrock Model Access", "sensitivity": "high"},
        {"type": "sagemaker", "name": "AWS SageMaker Endpoints", "sensitivity": "high"},
        {"type": "s3_data", "name": "AWS S3 Training Data", "sensitivity": "high"},
        {"type": "cloudwatch", "name": "AWS CloudWatch Logs", "sensitivity": "medium"},
    ],
    "Google AI": [
        {"type": "conversation_history", "name": "Gemini Conversation History", "sensitivity": "high"},
        {"type": "vertex_models", "name": "Vertex AI Models", "sensitivity": "high"},
        {"type": "gcs_data", "name": "GCS Training Data", "sensitivity": "high"},
    ],
    "GitHub": [
        {"type": "repositories", "name": "GitHub Repositories", "sensitivity": "high"},
        {"type": "actions_secrets", "name": "GitHub Actions Secrets", "sensitivity": "critical"},
    ],
    "GitHub Copilot": [
        {"type": "code_completions", "name": "Copilot Code Context", "sensitivity": "medium"},
    ],
    "Ollama": [
        {"type": "local_models", "name": "Ollama Local Model Weights", "sensitivity": "high"},
        {"type": "inference", "name": "Ollama Inference API", "sensitivity": "medium"},
    ],
    "LM Studio": [
        {"type": "local_models", "name": "LM Studio Local Model Weights", "sensitivity": "high"},
        {"type": "inference", "name": "LM Studio Inference API", "sensitivity": "medium"},
    ],
    "Jupyter": [
        {"type": "notebooks", "name": "Jupyter Notebooks & Kernels", "sensitivity": "high"},
        {"type": "shell_access", "name": "Jupyter Terminal Access", "sensitivity": "critical"},
    ],
    "Replicate": [
        {"type": "models", "name": "Replicate Models & Predictions", "sensitivity": "medium"},
        {"type": "billing", "name": "Replicate Billing", "sensitivity": "medium"},
    ],
    "Together AI": [
        {"type": "models", "name": "Together AI Models & Fine-Tunes", "sensitivity": "medium"},
        {"type": "billing", "name": "Together AI Billing", "sensitivity": "medium"},
    ],
    "Groq": [
        {"type": "inference", "name": "Groq Inference API", "sensitivity": "medium"},
        {"type": "billing", "name": "Groq Billing", "sensitivity": "medium"},
    ],
    "Slack": [
        {"type": "messages", "name": "Slack Messages & Channels", "sensitivity": "high"},
        {"type": "files", "name": "Slack Files & Uploads", "sensitivity": "high"},
    ],
    "Pinecone": [
        {"type": "vector_db", "name": "Pinecone Vector Database", "sensitivity": "high"},
    ],
    "Weaviate": [
        {"type": "vector_db", "name": "Weaviate Vector Database", "sensitivity": "high"},
    ],
}

# Network exposure service names (from notes like "Port 11434 detected as Ollama")
NETWORK_SERVICE_MAP: dict[str, str] = {
    "ollama": "Ollama",
    "lm studio": "LM Studio",
    "lm-studio": "LM Studio",
    "jupyter": "Jupyter",
    "gradio": "Gradio",
    "vllm": "vLLM",
    "localai": "LocalAI",
    "open webui": "Open WebUI",
    "open-webui": "Open WebUI",
    "comfyui": "ComfyUI",
    "text-generation-inference": "TGI",
}

# Scanners whose findings represent shell history entries
SHELL_HISTORY_SCANNERS = {"Shell History", "PowerShell Logs"}

# Scanners whose findings are browser sessions
BROWSER_SCANNERS = {"Browser Sessions"}

# Scanners whose findings are docker configs
DOCKER_SCANNERS = {"Docker"}

# Scanners whose findings are git credentials
GIT_SCANNERS = {"Git Credentials"}

# Scanners whose findings are jupyter instances
JUPYTER_SCANNERS = {"Jupyter"}


# ---------------------------------------------------------------------------
# ID generation
# ---------------------------------------------------------------------------

def _node_id(prefix: str, *parts: str) -> str:
    """Generate a deterministic 16-char hex node ID."""
    key = "|".join(parts)
    return f"{prefix}-{hashlib.sha256(key.encode()).hexdigest()[:16]}"


# ---------------------------------------------------------------------------
# Service inference
# ---------------------------------------------------------------------------

def _infer_service(finding: CredentialFinding) -> Optional[str]:
    """Infer the AI service a credential authenticates to."""
    cred_type = finding.credential_type

    # 1. Check credential_type for MCP env var names
    if cred_type.startswith("mcp_env:"):
        env_name = cred_type.split(":", 1)[1]
        svc = ENV_VAR_TO_SERVICE.get(env_name)
        if svc:
            return svc

    # 2. Check credential_type direct match
    if cred_type in CRED_TYPE_TO_SERVICE:
        svc = CRED_TYPE_TO_SERVICE[cred_type]
        if svc is not None:
            return svc

    # 3. Check env var name patterns in credential_type
    for env_var, svc in ENV_VAR_TO_SERVICE.items():
        if env_var.lower() in cred_type.lower():
            return svc

    # 4. Check value_preview prefix
    if finding.value_preview:
        for prefix in sorted(PREFIX_TO_SERVICE, key=len, reverse=True):
            if finding.value_preview.startswith(prefix):
                return PREFIX_TO_SERVICE[prefix]

    # 5. Fall back to tool_name
    svc = TOOL_TO_SERVICE.get(finding.tool_name)
    if svc:
        return svc

    return None


def _infer_network_service(finding: CredentialFinding) -> Optional[str]:
    """Infer the service from a network exposure finding's notes."""
    for note in finding.notes:
        note_lower = note.lower()
        for pattern, service in NETWORK_SERVICE_MAP.items():
            if pattern in note_lower:
                return service
    return None


def _extract_mcp_server_name(finding: CredentialFinding) -> Optional[str]:
    """Extract MCP server name from finding notes."""
    for note in finding.notes:
        if note.startswith("MCP server: "):
            return note[len("MCP server: "):]
    return None


def _storage_node_kind(finding: CredentialFinding) -> str:
    """Determine the storage node kind based on finding context."""
    if finding.tool_name in SHELL_HISTORY_SCANNERS:
        return "ShellHistory"
    if finding.tool_name in BROWSER_SCANNERS:
        return "BrowserSession"
    if finding.tool_name in DOCKER_SCANNERS:
        return "DockerConfig"
    if finding.tool_name in GIT_SCANNERS:
        return "GitCredential"
    if finding.tool_name in JUPYTER_SCANNERS:
        return "JupyterInstance"
    if finding.storage_type == StorageType.ENVIRONMENT_VAR:
        return "EnvVariable"
    if finding.storage_type in (StorageType.KEYCHAIN, StorageType.CREDENTIAL_MANAGER):
        return "CredentialStore"
    return "ConfigFile"


# ---------------------------------------------------------------------------
# Graph builder
# ---------------------------------------------------------------------------

class OpenGraphBuilder:
    """Builds BloodHound CE OpenGraph JSON from scan results."""

    def __init__(self) -> None:
        self._nodes: dict[str, dict] = {}  # id -> node dict
        self._edges: list[dict] = []
        self._seen_edges: set[str] = set()  # dedup key

    def _add_node(self, node_id: str, kinds: list[str], properties: dict) -> None:
        """Add a node, deduplicating by ID."""
        if node_id not in self._nodes:
            # Ensure all property values are OpenGraph-safe primitives
            safe_props = {}
            for k, v in properties.items():
                if v is None:
                    continue
                if k == "objectid":
                    continue  # reserved by OpenGraph
                # Convert to lowercase key
                key = k.lower()
                if isinstance(v, (str, int, float, bool)):
                    safe_props[key] = v
                elif isinstance(v, list) and all(isinstance(i, (str, int, float, bool)) for i in v):
                    safe_props[key] = v
                elif isinstance(v, datetime):
                    safe_props[key] = v.isoformat()
                else:
                    safe_props[key] = str(v)
            self._nodes[node_id] = {
                "id": node_id,
                "kinds": kinds,
                "properties": safe_props,
            }

    def _add_edge(self, start_id: str, end_id: str, kind: str,
                  properties: Optional[dict] = None) -> None:
        """Add an edge, deduplicating by (start, end, kind)."""
        dedup_key = f"{start_id}|{end_id}|{kind}"
        if dedup_key in self._seen_edges:
            return
        # Only add edge if both nodes exist
        if start_id not in self._nodes or end_id not in self._nodes:
            return
        self._seen_edges.add(dedup_key)
        edge = {
            "start": {"match_by": "id", "value": start_id},
            "end": {"match_by": "id", "value": end_id},
            "kind": kind,
        }
        if properties:
            safe_props = {
                k.lower(): v for k, v in properties.items()
                if v is not None and isinstance(v, (str, int, float, bool))
            }
            if safe_props:
                edge["properties"] = safe_props
        self._edges.append(edge)

    @staticmethod
    def _is_file_path(location: str) -> bool:
        """Check if a location string looks like a real file path."""
        if location.startswith(("process:", "tmux:", "screen:", "listening on ")):
            return False
        return "/" in location or "\\" in location

    def _process_finding(self, finding: CredentialFinding) -> None:
        """Process a single CredentialFinding into nodes and edges."""
        if not finding.exists:
            return

        # --- AICredential node ---
        cred_id = _node_id("aicred", finding.tool_name, finding.credential_type, finding.location)
        cred_name = f"{finding.tool_name}: {finding.credential_type}"
        cred_props = {
            "name": cred_name,
            "tool": finding.tool_name,
            "credential_type": finding.credential_type,
            "risk_level": finding.risk_level.value,
            "storage_type": finding.storage_type.value,
            "location": finding.location,
        }
        if finding.value_preview:
            cred_props["value_preview"] = finding.value_preview
        if finding.file_permissions:
            cred_props["file_permissions"] = finding.file_permissions
        if finding.expiry:
            cred_props["expiry"] = finding.expiry.isoformat()
        if finding.file_modified:
            cred_props["file_modified"] = finding.file_modified.isoformat()
        if finding.remediation:
            cred_props["remediation"] = finding.remediation
        if finding.notes:
            # Store notes as a single string (OpenGraph doesn't allow nested)
            cred_props["notes"] = " | ".join(finding.notes)

        self._add_node(cred_id, ["AICredential"], cred_props)

        # --- Storage node ---
        # Skip creating storage nodes for non-file locations (process PIDs,
        # tmux sessions, etc.) — these are runtime references, not files.
        if not self._is_file_path(finding.location):
            # Still create the tool node and service inference below
            tool_id = _node_id("tool", finding.tool_name)
            self._add_node(tool_id, ["AITool"], {"name": finding.tool_name})

            # Service inference still applies
            service = _infer_service(finding)
            if service:
                svc_id = _node_id("svc", service)
                self._add_node(svc_id, ["AIService"], {"name": service})
                self._add_edge(cred_id, svc_id, "Authenticates")
                self._create_data_store_edges(svc_id, service)
            return

        storage_kind = _storage_node_kind(finding)
        # Normalize location: strip :line_number suffixes for file paths
        loc = finding.location
        # Only strip colon suffix if it looks like :linenum (not C:\path)
        if ":" in loc and not loc[1:3] == ":\\":
            parts = loc.rsplit(":", 1)
            if len(parts) == 2 and parts[1].isdigit():
                loc = parts[0]

        storage_id = _node_id("stor", storage_kind, loc)
        storage_props = {
            "name": Path(loc).name if "/" in loc or "\\" in loc else loc,
            "path": loc,
            "kind_label": storage_kind,
        }
        if finding.file_permissions:
            storage_props["file_permissions"] = finding.file_permissions
        if finding.file_owner:
            storage_props["file_owner"] = finding.file_owner

        self._add_node(storage_id, [storage_kind], storage_props)

        # Credential -> StoredIn -> Storage
        self._add_edge(cred_id, storage_id, "StoredIn")
        # Storage -> ContainsCredential -> Credential
        self._add_edge(storage_id, cred_id, "ContainsCredential")

        # --- AITool node ---
        tool_id = _node_id("tool", finding.tool_name)
        self._add_node(tool_id, ["AITool"], {
            "name": finding.tool_name,
        })
        # Tool -> ReadsFrom -> storage (for file-based storage)
        if storage_kind in ("ConfigFile", "ShellHistory", "DockerConfig", "GitCredential", "JupyterInstance"):
            self._add_edge(tool_id, storage_id, "ReadsFrom")

        # --- Handle network exposure findings ---
        if finding.credential_type == "network_exposure":
            net_id = _node_id("net", finding.location)
            # Parse address:port from value_preview
            addr_port = finding.value_preview or finding.location
            self._add_node(net_id, ["NetworkEndpoint"], {
                "name": f"Network: {addr_port}",
                "address": addr_port,
                "risk_level": finding.risk_level.value,
            })
            # Infer the network service
            net_service = _infer_network_service(finding)
            if net_service:
                svc_id = _node_id("svc", net_service)
                self._add_node(svc_id, ["AIService"], {"name": net_service})
                self._add_edge(net_id, svc_id, "ExposesService")
                # Also create data stores for this service
                self._create_data_store_edges(svc_id, net_service)
            return  # Network findings don't have credential->service chain

        # --- AIService node (inferred) ---
        service = _infer_service(finding)
        if service:
            svc_id = _node_id("svc", service)
            self._add_node(svc_id, ["AIService"], {"name": service})
            # Credential -> Authenticates -> Service
            self._add_edge(cred_id, svc_id, "Authenticates")
            # Service -> GrantsAccessTo -> DataStores
            self._create_data_store_edges(svc_id, service)

        # --- MCP Server node ---
        mcp_name = _extract_mcp_server_name(finding)
        if mcp_name:
            config_path = finding.location.split(":")[0] if ":" in finding.location else finding.location
            mcp_id = _node_id("mcp", mcp_name, config_path)
            self._add_node(mcp_id, ["MCPServer"], {
                "name": f"MCP: {mcp_name}",
                "server_name": mcp_name,
                "config_path": config_path,
            })
            # Tool -> UsesMCPServer -> MCPServer
            self._add_edge(tool_id, mcp_id, "UsesMCPServer")
            # MCPServer -> RequiresCredential -> Credential
            self._add_edge(mcp_id, cred_id, "RequiresCredential")
            # MCPServer -> ConfiguredBy -> ConfigFile
            config_file_id = _node_id("stor", "ConfigFile", config_path)
            if config_file_id in self._nodes:
                self._add_edge(mcp_id, config_file_id, "ConfiguredBy")

            # If MCP env reference (${VAR}), create InheritsEnv edge
            if finding.credential_type.startswith("mcp_env:"):
                env_name = finding.credential_type.split(":", 1)[1]
                env_id = _node_id("stor", "EnvVariable", env_name)
                if env_id in self._nodes:
                    self._add_edge(mcp_id, env_id, "InheritsEnv")

        # --- Browser session edges ---
        if storage_kind == "BrowserSession" and service:
            svc_id = _node_id("svc", service)
            self._add_edge(storage_id, svc_id, "BrowserAuthTo")

        # --- Docker registry edges ---
        if storage_kind == "DockerConfig" and service:
            svc_id = _node_id("svc", service)
            self._add_edge(storage_id, svc_id, "DockerRegistryAuth")

        # --- Git credential edges ---
        if storage_kind == "GitCredential":
            # Try to infer service from git credential host
            git_service = self._infer_git_service(finding)
            if git_service:
                svc_id = _node_id("svc", git_service)
                self._add_node(svc_id, ["AIService"], {"name": git_service})
                self._add_edge(storage_id, svc_id, "GitAuthTo")

    def _create_data_store_edges(self, svc_id: str, service: str) -> None:
        """Create DataStore nodes and GrantsAccessTo edges for a service."""
        stores = SERVICE_DATA_STORES.get(service, [])
        for store in stores:
            ds_id = _node_id("data", service, store["type"])
            self._add_node(ds_id, ["DataStore"], {
                "name": store["name"],
                "store_type": store["type"],
                "service": service,
                "sensitivity": store["sensitivity"],
            })
            self._add_edge(svc_id, ds_id, "GrantsAccessTo")

    def _infer_git_service(self, finding: CredentialFinding) -> Optional[str]:
        """Infer service from git credential type (e.g., git_credential:github.com)."""
        cred_type = finding.credential_type
        if "github.com" in cred_type:
            return "GitHub"
        if "huggingface.co" in cred_type:
            return "Hugging Face"
        if "gitlab.com" in cred_type:
            return "GitLab"
        if "bitbucket.org" in cred_type:
            return "Bitbucket"
        return None

    def _detect_same_secrets(self) -> None:
        """Create SameSecret edges between credentials with identical value_preview."""
        # Group credentials by value_preview alone — the same secret can appear
        # under different credential_type names across scanners (e.g.,
        # "oauth_access_token" from Claude Code vs "live_oauth_session" from
        # Claude Sessions). The masked preview (prefix + last 4 chars) is
        # discriminating enough for same-secret detection.
        buckets: dict[str, list[str]] = {}
        for node_id, node in self._nodes.items():
            if node["kinds"][0] != "AICredential":
                continue
            props = node["properties"]
            preview = props.get("value_preview")
            if not preview or preview == "***REDACTED***":
                continue
            # Skip very short previews that are likely not real secrets
            if len(preview) < 10:
                continue
            bucket_key = preview
            buckets.setdefault(bucket_key, []).append(node_id)

        # Create bidirectional SameSecret edges within each bucket
        for bucket_key, node_ids in buckets.items():
            if len(node_ids) < 2:
                continue
            for i, id_a in enumerate(node_ids):
                for id_b in node_ids[i + 1:]:
                    self._add_edge(id_a, id_b, "SameSecret",
                                   {"confidence": "probable"})
                    self._add_edge(id_b, id_a, "SameSecret",
                                   {"confidence": "probable"})

    def build(self, results: list[ScanResult]) -> dict:
        """Build the complete OpenGraph JSON structure from scan results."""
        self._nodes.clear()
        self._edges.clear()
        self._seen_edges.clear()

        # Pass 1: Process all findings into nodes and edges
        for result in results:
            for finding in result.findings:
                self._process_finding(finding)

        # Pass 2: Detect same secrets across findings
        self._detect_same_secrets()

        # Build the OpenGraph JSON structure
        return {
            "metadata": {
                "source_kind": "AIHound",
            },
            "graph": {
                "nodes": list(self._nodes.values()),
                "edges": self._edges,
            },
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def export_opengraph(
    results: list[ScanResult],
    file: Optional[TextIO] = None,
    filepath: Optional[str] = None,
) -> str:
    """Export scan results as BloodHound OpenGraph JSON.

    Args:
        results: List of ScanResult from AIHound scanners.
        file: Optional file-like object to write to.
        filepath: Optional file path to write to (created with 0o600 permissions).

    Returns:
        The JSON string.
    """
    builder = OpenGraphBuilder()
    graph = builder.build(results)

    json_str = json.dumps(graph, indent=2)

    if filepath:
        fd = os.open(str(filepath), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(fd, "w", encoding="utf-8") as f:
            f.write(json_str)
    elif file:
        print(json_str, file=file)

    return json_str
