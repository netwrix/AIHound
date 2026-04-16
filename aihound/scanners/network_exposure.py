"""Scanner for AI-service network exposure via listening ports."""

from __future__ import annotations

import logging
import re
import subprocess

from aihound.core.scanner import (
    BaseScanner, CredentialFinding, ScanResult, StorageType, RiskLevel,
)
from aihound.core.platform import detect_platform, Platform
from aihound.remediation import hint_network_bind
from aihound.scanners import register

logger = logging.getLogger("aihound.scanners.network_exposure")

# Common AI service ports to check.
# NOTE: Ports 11434 (Ollama) and 1234 (LM Studio) are intentionally excluded —
# those scanners perform their own network binding checks.
AI_PORTS = {
    8888: "Jupyter Notebook/Lab",
    7860: "Gradio / text-generation-webui",
    8000: "vLLM",
    8080: "LocalAI",
    3000: "Open WebUI",
    8188: "ComfyUI",
}


@register
class NetworkExposureScanner(BaseScanner):
    def name(self) -> str:
        return "AI Network Exposure"

    def slug(self) -> str:
        return "network-exposure"

    def is_applicable(self) -> bool:
        # ss(8) is Linux-only; WSL also has it. macOS and native Windows don't.
        plat = detect_platform()
        return plat in (Platform.LINUX, Platform.WSL)

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        try:
            proc = subprocess.run(
                ["ss", "-tlnp"],
                capture_output=True, text=True, timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as e:
            logger.debug("ss not available or timed out: %s", e)
            result.errors.append(f"ss command failed: {e}")
            return result

        if proc.returncode != 0:
            logger.debug("ss returned non-zero: %s", proc.returncode)
            return result

        for line in proc.stdout.splitlines():
            for port, service in AI_PORTS.items():
                self._check_line_for_port(line, port, service, result)

        return result

    def _check_line_for_port(
        self, line: str, port: int, service: str, result: ScanResult
    ) -> None:
        """Check a single ss output line for a given port and record findings."""
        # Match patterns like "0.0.0.0:8888", "[::]:8888", or "192.168.1.5:8888"
        # in the Local Address:Port column. ss output uses whitespace-separated columns,
        # so scan the line for any "<addr>:<port>" token.
        port_str = f":{port}"

        # Find all address:port tokens on this line that end in our port
        # Token boundary: whitespace on either side, and the local address is typically
        # the 4th column in "ss -tlnp" output (State Recv-Q Send-Q LocalAddr:Port ...).
        matches = re.findall(rf"(\S+):{port}\b", line)
        if not matches:
            return

        for addr in matches:
            # Strip IPv6 brackets
            clean_addr = addr.strip("[]")

            # Ignore loopback bindings
            if clean_addr in ("127.0.0.1", "::1"):
                continue

            # Skip if this looks like a process/PID reference rather than a bind address
            # (ss includes "pid=1234,fd=5" style text in the Process column)
            if "pid=" in addr or "fd=" in addr:
                continue

            # Skip if there are non-IP characters we wouldn't expect in a bind address
            # (accept only digits, dots, colons, letters a-f, and brackets)
            if not re.fullmatch(r"[0-9a-fA-F.:\[\]*]+", addr):
                continue

            if clean_addr in ("0.0.0.0", "::", "*"):
                risk = RiskLevel.CRITICAL
                exposure_note = (
                    f"{service} listening on all interfaces ({clean_addr}:{port})"
                )
            else:
                # A specific non-loopback address (LAN IP, public IP, etc.)
                risk = RiskLevel.HIGH
                exposure_note = (
                    f"{service} listening on {clean_addr}:{port} (non-loopback)"
                )

            result.findings.append(CredentialFinding(
                tool_name=self.name(),
                credential_type="network_exposure",
                storage_type=StorageType.UNKNOWN,
                location=f"listening on {clean_addr}:{port}",
                exists=True,
                risk_level=risk,
                value_preview=f"{clean_addr}:{port}",
                remediation=(
                    f"Bind {service} to 127.0.0.1 instead of 0.0.0.0, "
                    f"or use an authentication proxy"
                ),
                remediation_hint=hint_network_bind(service, None, port),
                notes=[
                    exposure_note,
                    "Most AI service web UIs have no built-in authentication",
                    f"Port {port} detected as {service}",
                ],
            ))
