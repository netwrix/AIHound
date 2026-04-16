"""CLI entry point for AIHound."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from aihound import __version__
from aihound.core.platform import detect_platform
from aihound.scanners import get_all_scanners
from aihound.output.table import print_banner, print_results
from aihound.output.json_export import export_json
from aihound.output.html_report import export_html

logger = logging.getLogger("aihound")

# Resolve the banner image path relative to the project root
_PACKAGE_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _PACKAGE_DIR.parent
_DEFAULT_BANNER = _PROJECT_ROOT / "aihound.png"


def _setup_logging(verbose: bool = False, json_output: bool = False) -> None:
    """Configure logging levels and format.

    - Default: WARNING and above (quiet — only problems)
    - --verbose: DEBUG and above (scanner progress, paths checked, stack traces on errors)
    - --json: logs go to stderr so stdout stays clean for JSON
    """
    level = logging.DEBUG if verbose else logging.WARNING
    stream = sys.stderr if json_output else sys.stdout
    handler = logging.StreamHandler(stream)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))

    root = logging.getLogger("aihound")
    root.setLevel(level)
    root.handlers = [handler]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aihound",
        description="AIHound - AI Credential & Secrets Scanner",
    )
    parser.add_argument(
        "--version", action="version", version=f"aihound {__version__}"
    )
    parser.add_argument(
        "--show-secrets",
        action="store_true",
        help="Show actual credential values (USE WITH CAUTION)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as JSON to stdout",
    )
    parser.add_argument(
        "--json-file",
        type=str,
        metavar="PATH",
        help="Write JSON report to file",
    )
    parser.add_argument(
        "--html-file",
        type=str,
        metavar="PATH",
        help="Write HTML report to file",
    )
    parser.add_argument(
        "--banner",
        type=str,
        metavar="PATH",
        help="Custom banner image for HTML report (default: aihound.png)",
    )
    parser.add_argument(
        "--tools",
        nargs="+",
        metavar="TOOL",
        help="Only scan specific tools (use slugs from --list-tools)",
    )
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="List all available scanners and exit",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show debug output (paths checked, errors, stack traces)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )

    # Watch/monitor mode flags
    watch_group = parser.add_argument_group(
        "watch mode", "Continuous monitoring: re-scan on an interval and emit events on changes"
    )
    watch_group.add_argument(
        "--watch",
        action="store_true",
        help="Run continuously, alerting on new/changed credentials (Ctrl+C to stop)",
    )
    watch_group.add_argument(
        "--interval",
        type=float,
        default=30.0,
        metavar="SECONDS",
        help="Polling interval in seconds (default: 30)",
    )
    watch_group.add_argument(
        "--watch-log",
        type=str,
        metavar="PATH",
        help="Append watch events as NDJSON to this file",
    )
    watch_group.add_argument(
        "--notify",
        action="store_true",
        help="Fire OS-native desktop notifications for watch events",
    )
    watch_group.add_argument(
        "--notify-min-risk",
        type=str,
        choices=["critical", "high", "medium", "low", "info"],
        default="high",
        metavar="LEVEL",
        help="Minimum risk level to notify on (default: high)",
    )
    watch_group.add_argument(
        "--min-risk",
        type=str,
        choices=["critical", "high", "medium", "low", "info"],
        default="info",
        metavar="LEVEL",
        help="Minimum risk level for watch events (default: info — show all)",
    )
    watch_group.add_argument(
        "--debounce",
        type=float,
        default=10.0,
        metavar="SECONDS",
        help="Suppress duplicate events within this window (default: 10, 0 disables)",
    )

    # MCP server mode
    mcp_group = parser.add_argument_group(
        "mcp server mode", "Expose AIHound to AI assistants via Model Context Protocol"
    )
    mcp_group.add_argument(
        "--mcp",
        action="store_true",
        help=(
            "Run as an MCP stdio server. Requires `pip install aihound[mcp]`. "
            "Use in an MCP client config (e.g. claude_desktop_config.json) rather "
            "than invoking directly."
        ),
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # MCP server mode takes over immediately — no banner, no scan, no output formatting.
    # Logs go to stderr so stdout stays clean for JSON-RPC.
    if args.mcp:
        return _run_mcp_mode(verbose=args.verbose)

    _setup_logging(verbose=args.verbose, json_output=args.json_output)

    scanners = get_all_scanners()

    # --list-tools
    if args.list_tools:
        print("Available scanners:")
        for s in scanners:
            applicable = "yes" if s.is_applicable() else "no (not applicable on this platform)"
            print(f"  {s.slug():<20} {s.name():<30} Applicable: {applicable}")
        return 0

    # --show-secrets safety gate
    show_secrets = False
    if args.show_secrets:
        if sys.stdin.isatty():
            logger.warning(
                "--show-secrets will display raw credential values. "
                "Only use on YOUR OWN machine for research purposes."
            )
            try:
                confirm = input("Type 'YES' to confirm: ")
                if confirm.strip() != "YES":
                    print("Aborted.")
                    return 1
            except (EOFError, KeyboardInterrupt):
                print("\nAborted.")
                return 1
        show_secrets = True

    # Filter scanners
    if args.tools:
        tool_slugs = set(args.tools)
        scanners = [s for s in scanners if s.slug() in tool_slugs]
        if not scanners:
            logger.error("No scanners matched: %s — use --list-tools to see available scanners.", args.tools)
            return 1

    # Filter by platform applicability
    scanners = [s for s in scanners if s.is_applicable()]

    # Watch/monitor mode: takes over and never reaches the one-shot output path below
    if args.watch:
        return _run_watch_mode(scanners, args, show_secrets)

    # Print banner (unless JSON-only output)
    if not args.json_output:
        plat = detect_platform()
        print_banner(no_color=args.no_color)
        print(f"Platform: {plat.value}")
        if plat.value == "wsl":
            print("WSL detected - scanning both Linux and Windows credential paths\n")
        else:
            print()

    # Run scanners
    results = []
    for scanner in scanners:
        logger.debug("Scanning: %s...", scanner.name())
        result = scanner.run(show_secrets=show_secrets)
        results.append(result)

        for err in result.errors:
            logger.warning("[%s] %s", scanner.name(), err)

    # Output
    if args.json_output:
        export_json(results, file=sys.stdout)
    else:
        print_results(results, no_color=args.no_color, verbose=args.verbose)

    if args.json_file:
        out_path = _prepare_output_path(args.json_file, "JSON")
        if out_path is None:
            return 1
        try:
            export_json(results, filepath=str(out_path))
        except OSError as e:
            print(f"ERROR: Failed to write JSON report to {out_path}: {e}", file=sys.stderr)
            return 1
        logger.info("JSON report written to: %s", out_path)
        if not args.json_output:
            print(f"\nJSON report written to: {out_path}")

    if args.html_file:
        out_path = _prepare_output_path(args.html_file, "HTML")
        if out_path is None:
            return 1
        banner = Path(args.banner).expanduser() if args.banner else _DEFAULT_BANNER
        try:
            export_html(results, filepath=str(out_path), banner_path=banner)
        except OSError as e:
            print(f"ERROR: Failed to write HTML report to {out_path}: {e}", file=sys.stderr)
            return 1
        logger.info("HTML report written to: %s", out_path)
        if not args.json_output:
            print(f"HTML report written to: {out_path}")

    return 0


def _prepare_output_path(raw_path: str, label: str) -> Path | None:
    """Normalize an output file path: expand ~, resolve, auto-create parent dir.

    Returns the resolved Path on success, None on failure (after printing an error).
    """
    try:
        path = Path(raw_path).expanduser()
    except (RuntimeError, ValueError) as e:
        print(f"ERROR: Invalid {label} output path '{raw_path}': {e}", file=sys.stderr)
        return None

    parent = path.parent
    if parent and not parent.exists():
        try:
            parent.mkdir(parents=True, exist_ok=True)
            logger.debug("Created parent directory: %s", parent)
        except OSError as e:
            print(
                f"ERROR: Cannot create directory {parent} for {label} output: {e}\n"
                f"       Check that you have write permission to this location.",
                file=sys.stderr,
            )
            return None

    # Preflight write permission check
    if path.exists():
        if not path.is_file():
            print(
                f"ERROR: {label} output path {path} exists but is not a regular file.",
                file=sys.stderr,
            )
            return None
    return path


def _run_watch_mode(scanners: list, args: argparse.Namespace, show_secrets: bool) -> int:
    """Entry point for --watch. Builds sinks, starts the watch loop."""
    # Import here to keep watch-mode deps lazy
    from aihound.core.scanner import RiskLevel
    from aihound.watch import WatchLoop
    from aihound.output.watch_formatters import (
        NDJSONEventSink,
        NotificationEventSink,
        TerminalEventSink,
    )

    risk_map = {
        "critical": RiskLevel.CRITICAL,
        "high": RiskLevel.HIGH,
        "medium": RiskLevel.MEDIUM,
        "low": RiskLevel.LOW,
        "info": RiskLevel.INFO,
    }
    min_risk = risk_map[args.min_risk]
    notify_min_risk = risk_map[args.notify_min_risk]

    # Build sinks
    sinks = []

    if args.json_output:
        # In JSON mode, NDJSON to stdout is the primary output
        sinks.append(NDJSONEventSink(file=sys.stdout))
    else:
        # Otherwise terminal is primary — banner + live events
        plat = detect_platform()
        print_banner(no_color=args.no_color)
        print(f"Platform: {plat.value}")
        if plat.value == "wsl":
            print("WSL detected - scanning both Linux and Windows credential paths")
        print(
            f"Watch mode: interval={int(args.interval)}s, scanners={len(scanners)}, "
            f"min-risk={args.min_risk}. Press Ctrl+C to stop.\n"
        )
        sinks.append(TerminalEventSink(no_color=args.no_color))

    if args.watch_log:
        try:
            sinks.append(NDJSONEventSink(filepath=args.watch_log))
        except OSError as e:
            print(f"ERROR: Cannot open watch log {args.watch_log}: {e}", file=sys.stderr)
            return 1

    if args.notify:
        sinks.append(NotificationEventSink(min_risk=notify_min_risk))

    loop = WatchLoop(
        scanners=scanners,
        sinks=sinks,
        interval=args.interval,
        min_risk=min_risk,
        debounce_seconds=args.debounce,
        show_secrets=show_secrets,
    )

    try:
        event_count = loop.run()
    except KeyboardInterrupt:
        event_count = 0

    # Close any owned file handles in sinks
    for sink in sinks:
        close = getattr(sink, "close", None)
        if callable(close):
            close()

    # Final summary to stderr so it doesn't pollute NDJSON stdout
    if not args.json_output:
        print(f"\nWatch stopped. {event_count} event(s) emitted.", file=sys.stderr)
    return 0


def _run_mcp_mode(verbose: bool = False) -> int:
    """Entry point for --mcp. Runs AIHound as an MCP stdio server.

    Prints a friendly install hint (to stderr) and exits 1 if the optional
    `mcp` SDK isn't installed.
    """
    # All logging to stderr — stdout is reserved for JSON-RPC
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    root = logging.getLogger("aihound")
    root.setLevel(level)
    root.handlers = [handler]

    try:
        from aihound.mcp_server import run_server
    except ImportError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    try:
        run_server()
    except ImportError as e:
        # run_server() raises ImportError with a helpful message when the mcp SDK is missing
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        logger.debug("MCP server interrupted")

    return 0


if __name__ == "__main__":
    sys.exit(main())
