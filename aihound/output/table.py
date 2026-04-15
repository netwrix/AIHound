"""CLI table output for scan results."""

from __future__ import annotations

import sys
from typing import TextIO

from aihound.core.scanner import ScanResult, CredentialFinding, RiskLevel
from aihound.core.permissions import describe_permissions


# ANSI color codes
COLORS = {
    RiskLevel.CRITICAL: "\033[91m",  # Red
    RiskLevel.HIGH: "\033[93m",      # Yellow
    RiskLevel.MEDIUM: "\033[33m",    # Orange-ish
    RiskLevel.LOW: "\033[92m",       # Green
    RiskLevel.INFO: "\033[36m",      # Cyan
}
RESET = "\033[0m"
BOLD = "\033[1m"


def _truncate(s: str, width: int) -> str:
    if len(s) <= width:
        return s
    return s[: width - 3] + "..."


def print_banner(file: TextIO = sys.stdout, no_color: bool = False) -> None:
    b = BOLD if not no_color else ""
    r = RESET if not no_color else ""
    print(f"""
{b}╔══════════════════════════════════════════════════════════════╗
║          AIHound - AI Credential & Secrets Scanner           ║
╚══════════════════════════════════════════════════════════════╝{r}
""", file=file)


def print_results(
    results: list[ScanResult],
    file: TextIO = sys.stdout,
    no_color: bool = False,
    verbose: bool = False,
) -> None:
    """Print scan results as a formatted table."""
    all_findings: list[CredentialFinding] = []
    all_errors: list[str] = []

    for r in results:
        all_findings.extend(r.findings)
        all_errors.extend(r.errors)

    if not all_findings:
        print("No AI credentials found.", file=file)
        if all_errors and verbose:
            print("\nErrors:", file=file)
            for err in all_errors:
                print(f"  - {err}", file=file)
        return

    # Column widths
    col_tool = 16
    col_type = 22
    col_storage = 12
    col_location = 35
    col_risk = 8

    # Header
    header = (
        f"{'Tool':<{col_tool}} "
        f"{'Credential Type':<{col_type}} "
        f"{'Storage':<{col_storage}} "
        f"{'Location':<{col_location}} "
        f"{'Risk':<{col_risk}}"
    )
    sep = "-" * len(header)

    print(sep, file=file)
    b = BOLD if not no_color else ""
    r = RESET if not no_color else ""
    print(f"{b}{header}{r}", file=file)
    print(sep, file=file)

    for f in sorted(all_findings, key=lambda x: _risk_sort_key(x.risk_level)):
        color = COLORS.get(f.risk_level, "") if not no_color else ""
        reset = RESET if not no_color else ""

        risk_str = f"{color}{f.risk_level.value.upper()}{reset}"

        line = (
            f"{_truncate(f.tool_name, col_tool):<{col_tool}} "
            f"{_truncate(f.credential_type, col_type):<{col_type}} "
            f"{_truncate(f.storage_type.value, col_storage):<{col_storage}} "
            f"{_truncate(f.location, col_location):<{col_location}} "
            f"{risk_str}"
        )
        print(line, file=file)

        # Print value preview on next line if available
        if f.value_preview:
            print(f"  {'':>{col_tool}} Value: {f.value_preview}", file=file)

        # Print notes if verbose
        if verbose and f.notes:
            for note in f.notes:
                print(f"  {'':>{col_tool}} Note: {note}", file=file)

        if verbose and f.file_permissions:
            desc = describe_permissions(f.file_permissions)
            print(f"  {'':>{col_tool}} Perms: {f.file_permissions} ({desc}) Owner: {f.file_owner or 'N/A'}", file=file)

    print(sep, file=file)

    # Summary
    counts = {}
    for f in all_findings:
        counts[f.risk_level] = counts.get(f.risk_level, 0) + 1

    summary_parts = [f"{len(all_findings)} findings"]
    for level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]:
        if level in counts:
            color = COLORS.get(level, "") if not no_color else ""
            reset = RESET if not no_color else ""
            summary_parts.append(f"{color}{counts[level]} {level.value.upper()}{reset}")

    print(f"\nSummary: {' | '.join(summary_parts)}", file=file)

    if all_errors and verbose:
        print(f"\nErrors ({len(all_errors)}):", file=file)
        for err in all_errors:
            print(f"  - {err}", file=file)


def _risk_sort_key(risk: RiskLevel) -> int:
    order = {
        RiskLevel.CRITICAL: 0,
        RiskLevel.HIGH: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.LOW: 3,
        RiskLevel.INFO: 4,
    }
    return order.get(risk, 5)
