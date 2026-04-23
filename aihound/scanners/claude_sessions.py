"""Scanner for active Claude Code sessions and remote-control indicators.

Detects:
- Running `claude` CLI processes (local and SSH-originated)
- Active session files in ~/.claude/sessions/ with live PIDs
- Claude MCP server listening on non-loopback addresses
- OAuth tokens with non-expired access tokens (live session indicator)
- tmux/screen sessions hosting Claude processes (persistent remote access)

Security relevance: an active Claude Code session has full filesystem + bash
access. If the session is accessible remotely (via SSH, tmux, or an exposed
MCP server), it's a lateral-movement / privilege-escalation surface.
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger("aihound.scanners.claude_sessions")

from aihound.core.scanner import (
    BaseScanner, CredentialFinding, ScanResult, StorageType, RiskLevel,
)
from aihound.core.platform import detect_platform, Platform, get_home, get_wsl_windows_home
from aihound.core.redactor import mask_value
from aihound.core.permissions import (
    get_file_permissions, get_file_owner, get_file_mtime, describe_staleness,
)
from aihound.remediation import hint_manual, hint_run_command, hint_network_bind
from aihound.scanners import register


@register
class ClaudeSessionsScanner(BaseScanner):
    def name(self) -> str:
        return "Claude Sessions"

    def slug(self) -> str:
        return "claude-sessions"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        # 1. Detect running claude processes
        self._scan_processes(result, plat, show_secrets)

        # 2. Check session files in ~/.claude/sessions/
        self._scan_session_files(result, plat, show_secrets)

        # 3. Check for live (non-expired) OAuth tokens
        self._scan_live_tokens(result, plat, show_secrets)

        # 4. Check for tmux/screen sessions hosting claude
        self._scan_terminal_multiplexers(result, plat, show_secrets)

        # 5. Check for Claude MCP server listening (claude mcp serve)
        self._scan_mcp_serve(result, plat, show_secrets)

        return result

    # ------------------------------------------------------------------
    # 1. Running process detection
    # ------------------------------------------------------------------

    def _scan_processes(self, result: ScanResult, plat: Platform, show_secrets: bool) -> None:
        if plat == Platform.WINDOWS:
            self._scan_processes_windows(result, show_secrets)
        else:
            self._scan_processes_unix(result, plat, show_secrets)

    def _scan_processes_unix(self, result: ScanResult, plat: Platform, show_secrets: bool) -> None:
        """Detect running claude processes on Linux/macOS/WSL."""
        try:
            proc = subprocess.run(
                ["ps", "aux"], capture_output=True, text=True, timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return

        # Get current SSH sessions for cross-referencing
        ssh_sessions = self._get_ssh_sessions()

        for line in proc.stdout.splitlines():
            # Match lines where the command is 'claude' or contains the claude-code path
            if not re.search(r'\bclaude\b', line):
                continue
            # Skip grep itself
            if 'grep' in line:
                continue

            parts = line.split(None, 10)
            if len(parts) < 11:
                continue

            user = parts[0]
            pid = parts[1]
            cmd = parts[10]

            # Determine if this is an SSH-originated session
            is_ssh = self._is_pid_under_ssh(pid, ssh_sessions)

            if is_ssh:
                risk = RiskLevel.HIGH
                notes = [
                    f"PID {pid} running as user '{user}'",
                    "Session originated from SSH (remote access)",
                    f"Command: {cmd[:120]}",
                ]
                remediation = (
                    "Review whether this remote Claude session is authorized. "
                    "Terminate with `kill {pid}` if unauthorized."
                )
                hint = hint_run_command([f"kill {pid}"], shell="bash")
            else:
                risk = RiskLevel.MEDIUM
                notes = [
                    f"PID {pid} running as user '{user}'",
                    "Local Claude Code session with filesystem + bash access",
                    f"Command: {cmd[:120]}",
                ]
                remediation = (
                    "Active Claude Code session detected. This has full filesystem "
                    "and shell access. Ensure the machine is physically secure."
                )
                hint = hint_manual(remediation)

            result.findings.append(CredentialFinding(
                tool_name=self.name(),
                credential_type="active_claude_session",
                storage_type=StorageType.UNKNOWN,
                location=f"process:{pid}",
                exists=True,
                risk_level=risk,
                notes=notes,
                remediation=remediation,
                remediation_hint=hint,
            ))

    def _scan_processes_windows(self, result: ScanResult, show_secrets: bool) -> None:
        """Detect Claude Desktop / Claude Code on native Windows."""
        try:
            proc = subprocess.run(
                ["tasklist.exe", "/FO", "CSV"],
                capture_output=True, text=True, timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return

        for line in proc.stdout.splitlines():
            line_lower = line.lower()
            if 'claude' not in line_lower:
                continue

            # CSV format: "ImageName","PID","SessionName","Session#","MemUsage"
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) < 2:
                continue

            image_name = parts[0]
            pid = parts[1]

            if 'claude' in image_name.lower():
                result.findings.append(CredentialFinding(
                    tool_name=self.name(),
                    credential_type="active_claude_process",
                    storage_type=StorageType.UNKNOWN,
                    location=f"process:{pid}",
                    exists=True,
                    risk_level=RiskLevel.INFO,
                    notes=[
                        f"Windows process: {image_name} (PID {pid})",
                        "Claude Desktop or Claude Code running on this machine",
                    ],
                    remediation="Review whether this Claude process is expected",
                    remediation_hint=hint_manual("Review whether this Claude process is expected"),
                ))

    # ------------------------------------------------------------------
    # 2. Session file detection
    # ------------------------------------------------------------------

    def _scan_session_files(self, result: ScanResult, plat: Platform, show_secrets: bool) -> None:
        sessions_dir = get_home() / ".claude" / "sessions"
        if not sessions_dir.is_dir():
            return

        live_pids = self._get_live_pids()

        for session_file in sessions_dir.glob("*.json"):
            try:
                data = json.loads(session_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue

            pid = data.get("pid")
            session_id = data.get("sessionId", "unknown")
            cwd = data.get("cwd", "unknown")
            started_at = data.get("startedAt")

            is_live = str(pid) in live_pids if pid else False

            if is_live:
                risk = RiskLevel.MEDIUM
                notes = [
                    f"Active session: PID {pid} is running",
                    f"Session ID: {session_id}",
                    f"Working directory: {cwd}",
                ]
                if started_at:
                    try:
                        start_dt = datetime.fromtimestamp(started_at / 1000, tz=timezone.utc)
                        notes.append(f"Started: {start_dt.strftime('%Y-%m-%d %H:%M UTC')}")
                    except (ValueError, OSError):
                        pass
            else:
                risk = RiskLevel.INFO
                notes = [
                    f"Stale session file: PID {pid} is NOT running",
                    f"Session ID: {session_id}",
                    f"Working directory: {cwd}",
                    "Session file exists but process has exited",
                ]

            mtime = get_file_mtime(session_file)
            if mtime:
                notes.append(f"File last modified: {describe_staleness(mtime)}")

            result.findings.append(CredentialFinding(
                tool_name=self.name(),
                credential_type="claude_session_file",
                storage_type=StorageType.PLAINTEXT_JSON,
                location=str(session_file),
                exists=True,
                risk_level=risk,
                file_permissions=get_file_permissions(session_file),
                file_owner=get_file_owner(session_file),
                file_modified=mtime,
                notes=notes,
                remediation=(
                    "Active session — ensure machine is secure"
                    if is_live else
                    f"Remove stale session file: rm {session_file}"
                ),
                remediation_hint=(
                    hint_manual("Active Claude session with filesystem access — ensure machine is secure")
                    if is_live else
                    hint_run_command([f"rm {session_file}"], shell="bash")
                ),
            ))

    # ------------------------------------------------------------------
    # 3. Live (non-expired) OAuth token check
    # ------------------------------------------------------------------

    def _scan_live_tokens(self, result: ScanResult, plat: Platform, show_secrets: bool) -> None:
        creds_path = get_home() / ".claude" / ".credentials.json"
        if not creds_path.exists():
            return

        try:
            data = json.loads(creds_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return

        # Check claudeAiOauth block for non-expired access token
        oauth = data.get("claudeAiOauth", {})
        if not isinstance(oauth, dict):
            return

        access_token = oauth.get("accessToken", "")
        expires_at = oauth.get("expiresAt")

        if not access_token:
            return

        now = datetime.now(timezone.utc)
        is_live = False
        expiry_str = ""

        if expires_at:
            try:
                # expiresAt is in milliseconds epoch
                exp_dt = datetime.fromtimestamp(expires_at / 1000, tz=timezone.utc)
                is_live = exp_dt > now
                expiry_str = exp_dt.strftime("%Y-%m-%d %H:%M UTC")
            except (ValueError, OSError):
                pass

        if is_live:
            live_pids = self._get_live_pids()
            claude_running = any('claude' in p for p in live_pids.values())

            risk = RiskLevel.HIGH if claude_running else RiskLevel.MEDIUM
            notes = [
                f"OAuth access token is live (expires: {expiry_str})",
            ]
            if claude_running:
                notes.append("Claude process IS running — session is actively authenticated")
            else:
                notes.append("No claude process found — token is live but may be unused")

            result.findings.append(CredentialFinding(
                tool_name=self.name(),
                credential_type="live_oauth_session",
                storage_type=StorageType.PLAINTEXT_JSON,
                location=str(creds_path),
                exists=True,
                risk_level=risk,
                value_preview=mask_value(access_token, show_full=show_secrets),
                raw_value=access_token if show_secrets else None,
                file_permissions=get_file_permissions(creds_path),
                file_owner=get_file_owner(creds_path),
                file_modified=get_file_mtime(creds_path),
                notes=notes,
                remediation=(
                    "Token is actively in use. To revoke, log out of Claude Code "
                    "(`claude logout`) or wait for token expiry."
                ),
                remediation_hint=hint_run_command(["claude logout"], shell="bash"),
            ))

    # ------------------------------------------------------------------
    # 4. tmux / screen session detection
    # ------------------------------------------------------------------

    def _scan_terminal_multiplexers(self, result: ScanResult, plat: Platform, show_secrets: bool) -> None:
        if plat == Platform.WINDOWS:
            return

        # Check tmux
        self._check_tmux(result, show_secrets)
        # Check screen
        self._check_screen(result, show_secrets)

    def _check_tmux(self, result: ScanResult, show_secrets: bool) -> None:
        try:
            proc = subprocess.run(
                ["tmux", "list-sessions", "-F",
                 "#{session_name}:#{session_id}:#{session_attached}"],
                capture_output=True, text=True, timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return

        if proc.returncode != 0:
            return

        for line in proc.stdout.strip().splitlines():
            parts = line.split(":")
            if len(parts) < 3:
                continue
            session_name = parts[0]
            attached = parts[2] == "1"

            # Check if any pane in this session is running claude
            try:
                pane_proc = subprocess.run(
                    ["tmux", "list-panes", "-t", session_name, "-F", "#{pane_current_command}"],
                    capture_output=True, text=True, timeout=5,
                )
                pane_cmds = pane_proc.stdout.strip().splitlines()
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

            has_claude = any('claude' in cmd.lower() for cmd in pane_cmds)
            if not has_claude:
                continue

            risk = RiskLevel.HIGH
            status = "attached" if attached else "detached (accessible remotely)"
            notes = [
                f"tmux session '{session_name}' contains a Claude process",
                f"Session status: {status}",
                "A detached tmux session with Claude persists after SSH disconnect",
            ]

            result.findings.append(CredentialFinding(
                tool_name=self.name(),
                credential_type="tmux_claude_session",
                storage_type=StorageType.UNKNOWN,
                location=f"tmux:{session_name}",
                exists=True,
                risk_level=risk,
                notes=notes,
                remediation=(
                    f"Review tmux session '{session_name}'. "
                    f"Kill with: tmux kill-session -t {session_name}"
                ),
                remediation_hint=hint_run_command(
                    [f"tmux kill-session -t {session_name}"], shell="bash"
                ),
            ))

    def _check_screen(self, result: ScanResult, show_secrets: bool) -> None:
        try:
            proc = subprocess.run(
                ["screen", "-ls"],
                capture_output=True, text=True, timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return

        # screen -ls output: "	12345.name\t(Detached)" or "(Attached)"
        for line in proc.stdout.splitlines():
            match = re.match(r'\s+(\d+)\.(\S+)\s+\((\w+)\)', line)
            if not match:
                continue

            pid = match.group(1)
            session_name = match.group(2)
            status = match.group(3)

            # Check if this screen session's children include claude
            try:
                ps_proc = subprocess.run(
                    ["ps", "--ppid", pid, "-o", "comm="],
                    capture_output=True, text=True, timeout=5,
                )
                children = ps_proc.stdout.strip().splitlines()
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

            has_claude = any('claude' in cmd.lower() for cmd in children)
            if not has_claude:
                continue

            result.findings.append(CredentialFinding(
                tool_name=self.name(),
                credential_type="screen_claude_session",
                storage_type=StorageType.UNKNOWN,
                location=f"screen:{pid}.{session_name}",
                exists=True,
                risk_level=RiskLevel.HIGH,
                notes=[
                    f"GNU Screen session '{session_name}' (PID {pid}) contains Claude",
                    f"Status: {status}",
                    "A detached screen session with Claude persists after SSH disconnect",
                ],
                remediation=f"Kill with: screen -S {pid}.{session_name} -X quit",
                remediation_hint=hint_run_command(
                    [f"screen -S {pid}.{session_name} -X quit"], shell="bash"
                ),
            ))

    # ------------------------------------------------------------------
    # 5. Claude MCP server exposure (claude mcp serve)
    # ------------------------------------------------------------------

    def _scan_mcp_serve(self, result: ScanResult, plat: Platform, show_secrets: bool) -> None:
        """Check if `claude mcp serve` is running and/or exposed on non-loopback."""
        if plat in (Platform.WINDOWS, Platform.MACOS):
            return  # ss not available

        try:
            proc = subprocess.run(
                ["ss", "-tlnp"], capture_output=True, text=True, timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return

        for line in proc.stdout.splitlines():
            if 'claude' not in line.lower() and 'node' not in line.lower():
                continue

            # Look for any listening socket associated with claude
            if 'claude' in line.lower():
                # Check if bound to 0.0.0.0 or a non-loopback address
                if '0.0.0.0:' in line or ':::' in line or '*:' in line:
                    # Extract port
                    port_match = re.search(r'(?:0\.0\.0\.0|:::|\*):(\d+)', line)
                    port = port_match.group(1) if port_match else "unknown"

                    result.findings.append(CredentialFinding(
                        tool_name=self.name(),
                        credential_type="claude_mcp_server_exposed",
                        storage_type=StorageType.UNKNOWN,
                        location=f"0.0.0.0:{port}",
                        exists=True,
                        risk_level=RiskLevel.CRITICAL,
                        notes=[
                            f"Claude MCP server listening on 0.0.0.0:{port}",
                            "Any machine on the network can connect to this Claude instance",
                            "This grants remote code execution via Claude's tools",
                        ],
                        remediation=f"Bind Claude MCP server to 127.0.0.1 instead of 0.0.0.0",
                        remediation_hint=hint_network_bind("claude-mcp-serve", None, int(port) if port.isdigit() else 0),
                    ))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _get_ssh_sessions(self) -> list[dict]:
        """Return list of SSH session info dicts with user, tty, ip."""
        sessions = []
        try:
            proc = subprocess.run(
                ["who"], capture_output=True, text=True, timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return sessions

        for line in proc.stdout.splitlines():
            # who output: user  tty  date  (ip)
            parts = line.split()
            if len(parts) >= 5:
                ip_match = re.search(r'\((.+)\)', line)
                if ip_match:
                    sessions.append({
                        "user": parts[0],
                        "tty": parts[1],
                        "ip": ip_match.group(1),
                    })
        return sessions

    def _is_pid_under_ssh(self, pid: str, ssh_sessions: list[dict]) -> bool:
        """Check if a process was started from an SSH session by tracing its parent chain."""
        if not ssh_sessions:
            return False
        try:
            # Walk up the process tree looking for sshd
            current_pid = pid
            for _ in range(20):  # max depth to prevent infinite loops
                proc = subprocess.run(
                    ["ps", "-o", "ppid=,comm=", "-p", current_pid],
                    capture_output=True, text=True, timeout=2,
                )
                if proc.returncode != 0:
                    break
                parts = proc.stdout.strip().split(None, 1)
                if len(parts) < 2:
                    break
                ppid, comm = parts[0].strip(), parts[1].strip()
                if comm == "sshd":
                    return True
                if ppid in ("0", "1", current_pid):
                    break
                current_pid = ppid
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return False

    def _get_live_pids(self) -> dict[str, str]:
        """Return dict of {pid: command_name} for all running processes."""
        pids: dict[str, str] = {}
        try:
            proc = subprocess.run(
                ["ps", "-eo", "pid,comm"], capture_output=True, text=True, timeout=5,
            )
            for line in proc.stdout.splitlines()[1:]:  # skip header
                parts = line.split(None, 1)
                if len(parts) == 2:
                    pids[parts[0].strip()] = parts[1].strip()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return pids
