"""HTML report generator for AIHound scan results."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from aihound import __version__
from aihound.core.scanner import ScanResult, CredentialFinding, RiskLevel
from aihound.core.permissions import describe_permissions, describe_staleness


def _risk_color(risk: RiskLevel) -> str:
    return {
        RiskLevel.CRITICAL: "#e74c3c",
        RiskLevel.HIGH: "#e67e22",
        RiskLevel.MEDIUM: "#f1c40f",
        RiskLevel.LOW: "#2ecc71",
        RiskLevel.INFO: "#3498db",
    }.get(risk, "#95a5a6")


def _risk_bg(risk: RiskLevel) -> str:
    return {
        RiskLevel.CRITICAL: "rgba(231,76,60,0.15)",
        RiskLevel.HIGH: "rgba(230,126,34,0.15)",
        RiskLevel.MEDIUM: "rgba(241,196,15,0.10)",
        RiskLevel.LOW: "rgba(46,204,113,0.10)",
        RiskLevel.INFO: "rgba(52,152,219,0.10)",
    }.get(risk, "transparent")


def _encode_banner(banner_path: Optional[Path]) -> str:
    """Encode banner image as base64 data URI for embedding in HTML."""
    if not banner_path or not banner_path.exists():
        return ""

    try:
        data = banner_path.read_bytes()
        suffix = banner_path.suffix.lower()
        mime = {
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".gif": "image/gif",
            ".svg": "image/svg+xml",
            ".webp": "image/webp",
        }.get(suffix, "image/png")
        b64 = base64.b64encode(data).decode("ascii")
        return f"data:{mime};base64,{b64}"
    except OSError:
        return ""


def _risk_sort_key(risk: RiskLevel) -> int:
    return {
        RiskLevel.CRITICAL: 0, RiskLevel.HIGH: 1,
        RiskLevel.MEDIUM: 2, RiskLevel.LOW: 3, RiskLevel.INFO: 4,
    }.get(risk, 5)


def export_html(
    results: list[ScanResult],
    filepath: str,
    banner_path: Optional[Path] = None,
) -> None:
    """Generate a self-contained HTML report."""
    all_findings: list[CredentialFinding] = []
    all_errors: list[str] = []

    for r in results:
        all_findings.extend(r.findings)
        all_errors.extend(r.errors)

    # Sort by risk
    all_findings.sort(key=lambda f: _risk_sort_key(f.risk_level))

    # Risk counts
    counts: dict[RiskLevel, int] = {}
    for f in all_findings:
        counts[f.risk_level] = counts.get(f.risk_level, 0) + 1

    platform = results[0].platform if results else "unknown"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    banner_uri = _encode_banner(banner_path)

    # Build findings rows
    rows_html = ""
    for f in all_findings:
        color = _risk_color(f.risk_level)
        bg = _risk_bg(f.risk_level)
        notes_html = ""
        if f.notes:
            notes_html = "<br>".join(f'<span class="note">{n}</span>' for n in f.notes)
        perms_html = ""
        if f.file_permissions:
            desc = describe_permissions(f.file_permissions)
            perms_html = f'<span class="perms">Perms: {f.file_permissions} ({desc})</span>'
        expiry_html = ""
        if f.expiry:
            expiry_html = f'<span class="expiry">Expires: {f.expiry.strftime("%Y-%m-%d %H:%M UTC")}</span>'
        file_modified_html = ""
        if f.file_modified:
            file_modified_html = f'<span class="file-modified">Modified: {f.file_modified.strftime("%Y-%m-%d")} ({describe_staleness(f.file_modified)})</span>'
        remediation_html = ""
        if f.remediation:
            remediation_html = f'<span class="remediation">Fix: {_esc(f.remediation)}</span>'

        rows_html += f"""
        <tr style="background:{bg}">
            <td class="tool">{_esc(f.tool_name)}</td>
            <td class="cred-type">{_esc(f.credential_type)}</td>
            <td class="storage">{_esc(f.storage_type.value)}</td>
            <td class="location" title="{_esc(f.location)}">{_esc(f.location)}</td>
            <td class="value">{_esc(f.value_preview or '')}</td>
            <td class="risk" style="color:{color};font-weight:700">{f.risk_level.value.upper()}</td>
            <td class="details">{notes_html}{' ' if notes_html and perms_html else ''}{perms_html}{' ' if perms_html and expiry_html else ''}{expiry_html}{file_modified_html}{remediation_html}</td>
        </tr>"""

    # Summary badges
    badges_html = ""
    for level in [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]:
        c = counts.get(level, 0)
        if c > 0:
            badges_html += f'<span class="badge" style="background:{_risk_color(level)}">{c} {level.value.upper()}</span> '

    # Banner HTML
    banner_html = ""
    if banner_uri:
        banner_html = f'<div class="banner"><img src="{banner_uri}" alt="AIHound"></div>'

    # Errors section
    errors_html = ""
    if all_errors:
        errors_items = "".join(f"<li>{_esc(e)}</li>" for e in all_errors)
        errors_html = f"""
        <div class="errors">
            <h3>Errors</h3>
            <ul>{errors_items}</ul>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AIHound Scan Report</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
        background: #0a0e1a;
        color: #e0e6f0;
        line-height: 1.6;
    }}
    .banner {{
        text-align: center;
        padding: 30px 20px 10px;
        background: linear-gradient(135deg, #0d1224 0%, #1a1f3a 100%);
    }}
    .banner img {{
        max-width: 600px;
        width: 100%;
        height: auto;
        border-radius: 12px;
    }}
    .container {{
        max-width: 1400px;
        margin: 0 auto;
        padding: 20px;
    }}
    .meta {{
        display: flex;
        gap: 20px;
        flex-wrap: wrap;
        margin: 20px 0;
        padding: 15px 20px;
        background: rgba(255,255,255,0.05);
        border-radius: 8px;
        border: 1px solid rgba(255,255,255,0.08);
        font-size: 14px;
    }}
    .meta span {{ color: #8892b0; }}
    .meta strong {{ color: #ccd6f6; }}
    .summary {{
        margin: 20px 0;
        display: flex;
        align-items: center;
        gap: 12px;
        flex-wrap: wrap;
    }}
    .summary h2 {{
        font-size: 20px;
        color: #ccd6f6;
        margin-right: 8px;
    }}
    .badge {{
        display: inline-block;
        padding: 4px 14px;
        border-radius: 20px;
        font-size: 13px;
        font-weight: 700;
        color: #fff;
    }}
    table {{
        width: 100%;
        border-collapse: collapse;
        margin: 20px 0;
        font-size: 13px;
    }}
    th {{
        background: rgba(255,255,255,0.08);
        color: #8892b0;
        font-weight: 600;
        text-transform: uppercase;
        font-size: 11px;
        letter-spacing: 0.05em;
        padding: 12px 14px;
        text-align: left;
        border-bottom: 2px solid rgba(255,255,255,0.1);
        position: sticky;
        top: 0;
    }}
    td {{
        padding: 10px 14px;
        border-bottom: 1px solid rgba(255,255,255,0.05);
        vertical-align: top;
    }}
    tr:hover {{ background: rgba(255,255,255,0.03) !important; }}
    .tool {{ font-weight: 600; color: #ccd6f6; white-space: nowrap; }}
    .cred-type {{ color: #a8b2d1; }}
    .storage {{ color: #8892b0; font-size: 12px; }}
    .location {{
        font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
        font-size: 12px;
        color: #64ffda;
        max-width: 350px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }}
    .value {{
        font-family: 'SF Mono', 'Fira Code', 'Cascadia Code', monospace;
        font-size: 12px;
        color: #e6db74;
        max-width: 220px;
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
    }}
    .risk {{ text-align: center; font-size: 12px; white-space: nowrap; }}
    .details {{ font-size: 11px; color: #8892b0; }}
    .note {{ display: block; }}
    .perms, .expiry {{ display: block; color: #5a6580; }}
    .file-modified {{ display: block; color: #b0b0b0; font-size: 0.85em; margin-top: 2px; }}
    .remediation {{ display: block; color: #2ecc71; font-style: italic; margin-top: 4px; }}
    .errors {{
        margin: 20px 0;
        padding: 15px 20px;
        background: rgba(231,76,60,0.1);
        border: 1px solid rgba(231,76,60,0.3);
        border-radius: 8px;
    }}
    .errors h3 {{ color: #e74c3c; margin-bottom: 8px; font-size: 14px; }}
    .errors li {{ font-size: 13px; color: #e0a8a1; margin-left: 20px; }}
    .footer {{
        text-align: center;
        padding: 30px;
        color: #5a6580;
        font-size: 12px;
        border-top: 1px solid rgba(255,255,255,0.05);
        margin-top: 40px;
    }}
    @media (max-width: 900px) {{
        .location, .value {{ max-width: 180px; }}
        td, th {{ padding: 8px 8px; }}
    }}
</style>
</head>
<body>
    {banner_html}
    <div class="container">
        <div class="meta">
            <span>Platform: <strong>{_esc(platform)}</strong></span>
            <span>Scan Time: <strong>{timestamp}</strong></span>
            <span>Version: <strong>AIHound {__version__}</strong></span>
            <span>Total Findings: <strong>{len(all_findings)}</strong></span>
        </div>

        <div class="summary">
            <h2>Findings</h2>
            {badges_html}
        </div>

        <table>
            <thead>
                <tr>
                    <th>Tool</th>
                    <th>Credential Type</th>
                    <th>Storage</th>
                    <th>Location</th>
                    <th>Value Preview</th>
                    <th>Risk</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {rows_html}
            </tbody>
        </table>

        {errors_html}
    </div>

    <div class="footer">
        Generated by AIHound {__version__} &mdash; AI Credential &amp; Secrets Scanner
    </div>
</body>
</html>"""

    import os
    fd = os.open(str(filepath), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with open(fd, "w", encoding="utf-8") as f:
        f.write(html)


def _esc(text: str) -> str:
    """Escape HTML special characters."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
