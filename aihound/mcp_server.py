"""MCP (Model Context Protocol) server mode for AIHound.

Exposes AIHound's scanners to AI assistants (Claude Code, Claude Desktop, Cursor,
Windsurf, etc.) as structured tool calls. The assistant can run scans, enumerate
scanners, fetch remediation guidance, and check specific credentials — all via
stdio JSON-RPC.

Optional dependency: requires `pip install aihound[mcp]` which installs the
official `mcp` SDK. This module is ONLY imported when `aihound --mcp` is invoked,
so core AIHound works without the SDK installed.

Security model:
- Read-only. This server never modifies files.
- Raw credential values NEVER leave this process, regardless of any flag.
  The AI assistant gets `value_preview` (masked) and `remediation_hint` (a
  structured action the assistant can execute with ITS own filesystem tools).
- stdio transport only. No network exposure.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Optional

from aihound import __version__
from aihound.core.platform import detect_platform
from aihound.core.scanner import CredentialFinding, RiskLevel, ScanResult
from aihound.scanners import get_all_scanners

logger = logging.getLogger("aihound.mcp")


# Cache TTL for scan results — cheap defense against an AI assistant that calls
# `aihound_scan` repeatedly in the same conversation. 30 seconds balances freshness
# against avoiding 5+ second scan storms.
SCAN_CACHE_TTL = 30.0


@dataclass
class CachedScan:
    timestamp: float
    results: list[ScanResult]


# module-level cache; single-threaded server so no locking needed
_cache: dict[tuple, CachedScan] = {}


# ---------------------------------------------------------------------------
# Serialization — the boundary that keeps raw_value out of MCP responses
# ---------------------------------------------------------------------------


def _finding_id(f: CredentialFinding) -> str:
    """Stable opaque ID for a finding, usable as a reference in get_remediation calls."""
    raw = f"{f.tool_name}|{f.credential_type}|{f.location}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _finding_to_mcp(f: CredentialFinding) -> dict:
    """Convert a finding to its MCP response shape.

    Uses the existing to_dict() (which already strips raw_value) and adds the
    opaque `finding_id` for cross-tool references.
    """
    d = f.to_dict()
    # Defensive: guarantee raw_value is never in the payload even if to_dict changes
    d.pop("raw_value", None)
    d["finding_id"] = _finding_id(f)
    return d


def _results_to_mcp(results: list[ScanResult], version: str) -> dict:
    """Top-level MCP response shape for a scan."""
    all_findings: list[dict] = []
    all_errors: list[str] = []
    counts: dict[str, int] = {r.value: 0 for r in RiskLevel}

    for r in results:
        for f in r.findings:
            all_findings.append(_finding_to_mcp(f))
            counts[f.risk_level.value] += 1
        all_errors.extend(f"[{r.scanner_name}] {e}" for e in r.errors)

    platform_name = results[0].platform if results else detect_platform().value

    return {
        "scan_metadata": {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "platform": platform_name,
            "aihound_version": version,
        },
        "findings": all_findings,
        "errors": all_errors,
        "summary": {
            "total_findings": len(all_findings),
            "by_risk": counts,
        },
    }


# ---------------------------------------------------------------------------
# Scanning helpers
# ---------------------------------------------------------------------------


_RISK_ORDER = {
    RiskLevel.INFO: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


def _parse_risk(value: Optional[str]) -> Optional[RiskLevel]:
    if not value:
        return None
    try:
        return RiskLevel(value.lower())
    except ValueError:
        return None


def _filter_by_risk(results: list[ScanResult], min_risk: Optional[RiskLevel]) -> list[ScanResult]:
    if min_risk is None:
        return results
    threshold = _RISK_ORDER[min_risk]
    filtered = []
    for r in results:
        kept = [f for f in r.findings if _RISK_ORDER.get(f.risk_level, 0) >= threshold]
        filtered.append(ScanResult(
            scanner_name=r.scanner_name,
            platform=r.platform,
            findings=kept,
            errors=r.errors,
            scan_time=r.scan_time,
        ))
    return filtered


def _run_scan(tools: Optional[list[str]] = None, force: bool = False) -> list[ScanResult]:
    """Run the selected scanners, caching the result for SCAN_CACHE_TTL seconds."""
    cache_key = tuple(sorted(tools)) if tools else ()
    cached = _cache.get(cache_key)
    now = time.monotonic()
    if cached and not force and (now - cached.timestamp) < SCAN_CACHE_TTL:
        logger.debug("Returning cached scan (age %.1fs)", now - cached.timestamp)
        return cached.results

    scanners = get_all_scanners()
    if tools:
        tool_set = set(tools)
        scanners = [s for s in scanners if s.slug() in tool_set]
    scanners = [s for s in scanners if s.is_applicable()]

    results: list[ScanResult] = []
    for scanner in scanners:
        # Never pass show_secrets=True; MCP never exposes raw values
        result = scanner.run(show_secrets=False)
        results.append(result)

    _cache[cache_key] = CachedScan(timestamp=now, results=results)
    return results


# ---------------------------------------------------------------------------
# MCP server — lazy-built on run_server() to keep mcp SDK import optional
# ---------------------------------------------------------------------------


def _check_mcp_dep() -> None:
    """Raise ImportError with a helpful message if the mcp SDK isn't installed."""
    try:
        import mcp  # noqa: F401
    except ImportError:
        raise ImportError(
            "MCP server mode requires the `mcp` Python SDK.\n"
            "Install with:  pip install aihound[mcp]\n"
            "Or directly:   pip install mcp"
        )


def run_server() -> None:
    """Entry point for `aihound --mcp`. Blocks on stdio until the client disconnects.

    Raises ImportError (with install instructions) if the `mcp` SDK isn't available.
    """
    _check_mcp_dep()

    # Import is intentionally deferred so core AIHound works without mcp installed
    from mcp.server.fastmcp import FastMCP

    mcp_server = FastMCP("aihound")

    # ------- Tools -------

    @mcp_server.tool()
    def aihound_scan(
        tools: Optional[list[str]] = None,
        min_risk: Optional[str] = None,
        force: bool = False,
    ) -> dict:
        """Run AIHound's credential scanners and return structured findings.

        Args:
            tools: Optional list of scanner slugs (e.g. ["claude-code", "docker"]).
                   If omitted, runs all applicable scanners.
            min_risk: Optional minimum risk level ("critical", "high", "medium",
                      "low", "info"). Findings below this level are dropped.
            force: If True, bypass the 30-second scan cache.

        Returns:
            {scan_metadata, findings, errors, summary}. Findings never contain
            raw credential values — only masked previews plus a
            `remediation_hint` dict an agent can act on.
        """
        results = _run_scan(tools=tools, force=force)
        results = _filter_by_risk(results, _parse_risk(min_risk))
        return _results_to_mcp(results, __version__)

    @mcp_server.tool()
    def aihound_list_scanners() -> dict:
        """List all available AIHound scanners and whether they apply to this host."""
        scanners = get_all_scanners()
        items = []
        for s in scanners:
            items.append({
                "slug": s.slug(),
                "name": s.name(),
                "applicable": s.is_applicable(),
            })
        return {"scanners": items, "total": len(items)}

    @mcp_server.tool()
    def aihound_get_remediation(finding_id: str) -> dict:
        """Fetch remediation guidance for a finding by its opaque `finding_id`.

        Call `aihound_scan` first to get finding_ids. Returns the human-readable
        remediation string plus the structured remediation_hint dict.

        Args:
            finding_id: Opaque 16-char ID from a previous scan result.

        Returns:
            {finding_id, tool_name, credential_type, location, risk_level,
             remediation, remediation_hint}. Returns error if ID is not found
             in any cached scan.
        """
        for _, cached in _cache.items():
            for result in cached.results:
                for f in result.findings:
                    if _finding_id(f) == finding_id:
                        return {
                            "finding_id": finding_id,
                            "tool_name": f.tool_name,
                            "credential_type": f.credential_type,
                            "location": f.location,
                            "risk_level": f.risk_level.value,
                            "remediation": f.remediation,
                            "remediation_hint": f.remediation_hint,
                        }
        return {
            "error": f"No finding with id {finding_id} in cache. "
                     f"Call aihound_scan first or use force=True to refresh."
        }

    @mcp_server.tool()
    def aihound_check(tool: str, credential_type: Optional[str] = None) -> dict:
        """Run a single scanner. Useful when the AI only needs to check one tool.

        Bypasses the scan cache — always runs fresh.

        Args:
            tool: Scanner slug (e.g. "claude-code"). Use `aihound_list_scanners` for valid slugs.
            credential_type: Optional filter — only return findings of this type.

        Returns:
            Same shape as aihound_scan, but scoped to one scanner.
        """
        results = _run_scan(tools=[tool], force=True)
        if credential_type:
            for r in results:
                r.findings = [f for f in r.findings if f.credential_type == credential_type]
        return _results_to_mcp(results, __version__)

    # ------- Resources -------

    @mcp_server.resource("aihound://findings/latest")
    def findings_latest() -> str:
        """The most recent cached scan, or a fresh one if no cache exists."""
        results = _run_scan(tools=None, force=False)
        return json.dumps(_results_to_mcp(results, __version__), indent=2)

    @mcp_server.resource("aihound://platform")
    def platform_info() -> str:
        """Detected platform info — useful for the assistant to tailor advice."""
        plat = detect_platform()
        return json.dumps({
            "os": plat.value,
            "is_wsl": plat.value == "wsl",
            "aihound_version": __version__,
        }, indent=2)

    # ------- Run -------

    logger.info("AIHound MCP server starting (stdio transport, version %s)", __version__)
    mcp_server.run()
