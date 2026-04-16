// Command aihound is the CLI entry point for the AIHound credential scanner.
package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"aihound/core"
	"aihound/mcpserver"
	"aihound/output"
	"aihound/scanners"
	"aihound/watch"

	pflag "github.com/spf13/pflag"
	"golang.org/x/term"
)

// Version is the current AIHound version.
const Version = "3.0.0"

var (
	flagVersion     = pflag.Bool("version", false, "Show version")
	flagShowSecrets = pflag.Bool("show-secrets", false, "Display actual credential values (USE WITH CAUTION)")
	flagJSON        = pflag.Bool("json", false, "Output results as JSON to stdout")
	flagJSONFile    = pflag.String("json-file", "", "Write JSON report to file")
	flagHTMLFile    = pflag.String("html-file", "", "Write HTML report to file")
	flagBanner      = pflag.String("banner", "", "Custom banner image for HTML report")
	flagTools       = pflag.StringArray("tools", nil, "Scanner slugs to run (can be repeated)")
	flagListTools   = pflag.Bool("list-tools", false, "List all available scanners and exit")
	flagVerbose     = pflag.BoolP("verbose", "v", false, "Show debug output")
	flagNoColor     = pflag.Bool("no-color", false, "Disable ANSI colored output")

	// Watch mode flags
	flagWatch         = pflag.Bool("watch", false, "Run continuously, alert on new/changed credentials (Ctrl+C to stop)")
	flagInterval      = pflag.Float64("interval", 30.0, "Watch polling interval in seconds")
	flagWatchLog      = pflag.String("watch-log", "", "Append watch events as NDJSON to file")
	flagNotify        = pflag.Bool("notify", false, "Fire OS-native desktop notifications for watch events")
	flagNotifyMinRisk = pflag.String("notify-min-risk", "high", "Minimum risk to notify on (critical|high|medium|low|info)")
	flagMinRisk       = pflag.String("min-risk", "info", "Minimum risk level for watch events")
	flagDebounce      = pflag.Float64("debounce", 10.0, "Suppress duplicate events within this window in seconds (0 disables)")

	// MCP server mode flag
	flagMCP = pflag.Bool("mcp", false, "Run as an MCP stdio server (use in an MCP client config rather than invoking directly)")
)

func parseRiskLevel(s string) (core.RiskLevel, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return core.RiskCritical, nil
	case "high":
		return core.RiskHigh, nil
	case "medium":
		return core.RiskMedium, nil
	case "low":
		return core.RiskLow, nil
	case "info":
		return core.RiskInfo, nil
	default:
		return core.RiskInfo, fmt.Errorf("unknown risk level: %s", s)
	}
}

func main() {
	pflag.Parse()

	// --version
	if *flagVersion {
		fmt.Printf("aihound %s\n", Version)
		os.Exit(0)
	}

	// MCP server mode takes over immediately — no banner, no one-shot scan.
	// Logs (none in this binary, but any panic) go to stderr; stdout is reserved
	// for JSON-RPC.
	if *flagMCP {
		os.Exit(runMCPMode())
	}

	allScanners := scanners.GetAll()

	// --list-tools
	if *flagListTools {
		fmt.Println("Available scanners:")
		for _, s := range allScanners {
			applicable := "yes"
			if !s.IsApplicable() {
				applicable = "no (not applicable on this platform)"
			}
			fmt.Printf("  %-20s %-30s Applicable: %s\n", s.Slug(), s.Name(), applicable)
		}
		os.Exit(0)
	}

	// --show-secrets safety gate
	showSecrets := false
	if *flagShowSecrets {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			fmt.Fprintln(os.Stderr, "WARNING: --show-secrets will display raw credential values.")
			fmt.Fprintln(os.Stderr, "Only use on YOUR OWN machine for research purposes.")
			fmt.Fprint(os.Stderr, "Type YES to confirm: ")
			reader := bufio.NewReader(os.Stdin)
			confirm, err := reader.ReadString('\n')
			if err != nil {
				fmt.Fprintln(os.Stderr, "\nAborted.")
				os.Exit(1)
			}
			if strings.TrimSpace(confirm) != "YES" {
				fmt.Fprintln(os.Stderr, "Aborted.")
				os.Exit(1)
			}
		}
		showSecrets = true
	}

	// Filter by --tools if provided
	activeScanners := allScanners
	if flagTools != nil && len(*flagTools) > 0 {
		slugSet := make(map[string]bool)
		for _, slug := range *flagTools {
			slugSet[slug] = true
		}
		var filtered []core.Scanner
		for _, s := range activeScanners {
			if slugSet[s.Slug()] {
				filtered = append(filtered, s)
			}
		}
		if len(filtered) == 0 {
			fmt.Fprintf(os.Stderr, "No scanners matched: %v -- use --list-tools to see available scanners.\n", *flagTools)
			os.Exit(1)
		}
		activeScanners = filtered
	}

	// Filter by platform applicability
	{
		var applicable []core.Scanner
		for _, s := range activeScanners {
			if s.IsApplicable() {
				applicable = append(applicable, s)
			}
		}
		activeScanners = applicable
	}

	// Watch/monitor mode: takes over; never reaches the one-shot output path below.
	if *flagWatch {
		os.Exit(runWatchMode(activeScanners, showSecrets))
	}

	// Print banner (unless JSON-only output to stdout)
	if !*flagJSON {
		plat := core.DetectPlatform()
		printBanner(*flagNoColor)
		fmt.Printf("Platform: %s\n", plat)
		if plat == core.PlatformWSL {
			fmt.Println("WSL detected - scanning both Linux and Windows credential paths")
		}
		fmt.Println()
	}

	// Run scanners
	var results []core.ScanResult
	for _, scanner := range activeScanners {
		if *flagVerbose {
			log.Printf("Scanning: %s...", scanner.Name())
		}

		var result core.ScanResult
		func() {
			defer func() {
				if r := recover(); r != nil {
					result = core.ScanResult{
						ScannerName: scanner.Name(),
						Platform:    core.DetectPlatform().String(),
						Errors:      []string{fmt.Sprintf("panic: %v", r)},
					}
				}
			}()

			start := time.Now()
			result = scanner.Scan(showSecrets)
			result.ScanTime = time.Since(start).Seconds()
		}()

		results = append(results, result)

		if *flagVerbose {
			for _, err := range result.Errors {
				log.Printf("[%s] %s", scanner.Name(), err)
			}
		}
	}

	// Output: table (default) or JSON to stdout
	if *flagJSON {
		if err := output.WriteJSON(os.Stdout, results, Version); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing JSON: %v\n", err)
			os.Exit(1)
		}
	} else {
		output.PrintTable(os.Stdout, results, *flagVerbose, *flagNoColor)
	}

	// JSON file output
	if *flagJSONFile != "" {
		if err := output.WriteJSONFile(*flagJSONFile, results, Version); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing JSON file: %v\n", err)
			os.Exit(1)
		}
		if !*flagJSON {
			fmt.Printf("\nJSON report written to: %s\n", *flagJSONFile)
		}
	}

	// HTML file output
	if *flagHTMLFile != "" {
		bannerPath := *flagBanner
		if err := output.WriteHTMLReport(*flagHTMLFile, results, bannerPath, Version); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing HTML report: %v\n", err)
			os.Exit(1)
		}
		if !*flagJSON {
			fmt.Printf("HTML report written to: %s\n", *flagHTMLFile)
		}
	}
}

// runWatchMode implements --watch. Builds sinks, starts the watch loop, handles
// SIGINT/SIGTERM for graceful shutdown, and prints a final summary to stderr.
// Returns a process exit code.
func runWatchMode(activeScanners []core.Scanner, showSecrets bool) int {
	minRisk, err := parseRiskLevel(*flagMinRisk)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return 1
	}
	notifyMinRisk, err := parseRiskLevel(*flagNotifyMinRisk)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		return 1
	}

	// Build sinks
	var sinks []watch.EventSink
	var ndjsonFile *output.NDJSONEventSink

	if *flagJSON {
		// NDJSON to stdout is the primary output
		s := output.NewNDJSONEventSink(os.Stdout)
		sinks = append(sinks, s.Emit)
	} else {
		// Terminal is primary — banner + live events
		plat := core.DetectPlatform()
		printBanner(*flagNoColor)
		fmt.Printf("Platform: %s\n", plat)
		if plat == core.PlatformWSL {
			fmt.Println("WSL detected - scanning both Linux and Windows credential paths")
		}
		fmt.Printf(
			"Watch mode: interval=%ds, scanners=%d, min-risk=%s. Press Ctrl+C to stop.\n\n",
			int(*flagInterval), len(activeScanners), *flagMinRisk,
		)
		ts := &output.TerminalEventSink{Writer: os.Stdout, NoColor: *flagNoColor}
		sinks = append(sinks, ts.Emit)
	}

	if *flagWatchLog != "" {
		s, err := output.NewNDJSONEventSinkFile(*flagWatchLog)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Cannot open watch log %s: %v\n", *flagWatchLog, err)
			return 1
		}
		ndjsonFile = s
		sinks = append(sinks, s.Emit)
	}

	if *flagNotify {
		ns := &output.NotificationEventSink{MinRisk: notifyMinRisk}
		sinks = append(sinks, ns.Emit)
	}

	// Context wiring: SIGINT / SIGTERM triggers cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	loop := watch.NewWatchLoop(
		activeScanners,
		sinks,
		time.Duration(*flagInterval*float64(time.Second)),
		minRisk,
		time.Duration(*flagDebounce*float64(time.Second)),
		showSecrets,
	)

	eventCount, runErr := loop.Run(ctx)

	// Close owned file sinks
	if ndjsonFile != nil {
		_ = ndjsonFile.Close()
	}

	if !*flagJSON {
		fmt.Fprintf(os.Stderr, "\nWatch stopped. %d event(s) emitted.\n", eventCount)
	}
	if runErr != nil && runErr != context.Canceled {
		fmt.Fprintf(os.Stderr, "Watch loop error: %v\n", runErr)
		return 1
	}
	return 0
}

// runMCPMode implements --mcp. Runs the MCP stdio server until the client
// disconnects or SIGINT/SIGTERM. Returns a process exit code.
func runMCPMode() int {
	// Cancel context on SIGINT/SIGTERM so the server shuts down cleanly when
	// the client (e.g. Claude Desktop) terminates the subprocess.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	if err := mcpserver.Run(ctx, Version); err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "MCP server error: %v\n", err)
		return 1
	}
	return 0
}
