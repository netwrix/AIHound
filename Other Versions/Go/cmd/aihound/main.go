// Command aihound is the CLI entry point for the AIHound credential scanner.
package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"aihound/core"
	"aihound/output"
	"aihound/scanners"

	pflag "github.com/spf13/pflag"
	"golang.org/x/term"
)

// Version is the current AIHound version.
const Version = "0.2.0"

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
)

func main() {
	pflag.Parse()

	// --version
	if *flagVersion {
		fmt.Printf("aihound %s\n", Version)
		os.Exit(0)
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
