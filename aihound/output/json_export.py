"""JSON export for scan results."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO, Optional

from aihound import __version__
from aihound.core.scanner import ScanResult, RiskLevel


def export_json(
    results: list[ScanResult],
    file: Optional[TextIO] = None,
    filepath: Optional[str] = None,
) -> str:
    """Export scan results as JSON. Returns the JSON string."""
    all_findings = []
    all_errors = []

    for r in results:
        all_findings.extend(f.to_dict() for f in r.findings)
        all_errors.extend(r.errors)

    counts = {}
    for r in results:
        for f in r.findings:
            counts[f.risk_level] = counts.get(f.risk_level, 0) + 1

    report = {
        "scan_metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "platform": results[0].platform if results else "unknown",
            "aicreds_version": __version__,
        },
        "findings": all_findings,
        "errors": all_errors,
        "summary": {
            "total_findings": len(all_findings),
            "by_risk": {
                level.value: counts.get(level, 0)
                for level in RiskLevel
            },
        },
    }

    json_str = json.dumps(report, indent=2)

    if filepath:
        import os
        fd = os.open(str(filepath), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(fd, "w", encoding="utf-8") as f:
            f.write(json_str)
    elif file:
        print(json_str, file=file)

    return json_str
