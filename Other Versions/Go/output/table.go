// Package output provides formatted output for AIHound scan results.
package output

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"aihound/core"
)

// ANSI color codes for risk levels.
const (
	colorCritical = "\033[91m"  // Red
	colorHigh     = "\033[93m"  // Yellow
	colorMedium   = "\033[38;5;208m" // Orange
	colorLow      = "\033[92m"  // Green
	colorInfo     = "\033[90m"  // Gray
	colorReset    = "\033[0m"
	colorBold     = "\033[1m"
)

// Column widths for table output.
const (
	colTool     = 16
	colType     = 22
	colStorage  = 12
	colLocation = 35
	colRisk     = 8
)

func riskColor(r core.RiskLevel) string {
	switch r {
	case core.RiskCritical:
		return colorCritical
	case core.RiskHigh:
		return colorHigh
	case core.RiskMedium:
		return colorMedium
	case core.RiskLow:
		return colorLow
	case core.RiskInfo:
		return colorInfo
	default:
		return ""
	}
}

func riskSortKey(r core.RiskLevel) int {
	switch r {
	case core.RiskCritical:
		return 0
	case core.RiskHigh:
		return 1
	case core.RiskMedium:
		return 2
	case core.RiskLow:
		return 3
	case core.RiskInfo:
		return 4
	default:
		return 5
	}
}

func truncate(s string, width int) string {
	if len(s) <= width {
		return s
	}
	if width <= 3 {
		return s[:width]
	}
	return s[:width-3] + "..."
}

func padRight(s string, width int) string {
	if len(s) >= width {
		return s
	}
	return s + strings.Repeat(" ", width-len(s))
}

// PrintTable prints scan results as a formatted ANSI table to the given writer.
func PrintTable(w io.Writer, results []core.ScanResult, verbose bool, noColor bool) {
	var allFindings []core.CredentialFinding
	var allErrors []string

	for _, r := range results {
		allFindings = append(allFindings, r.Findings...)
		allErrors = append(allErrors, r.Errors...)
	}

	if len(allFindings) == 0 {
		fmt.Fprintln(w, "No AI credentials found.")
		if len(allErrors) > 0 && verbose {
			fmt.Fprintln(w, "\nErrors:")
			for _, e := range allErrors {
				fmt.Fprintf(w, "  - %s\n", e)
			}
		}
		return
	}

	// Sort findings: Critical first, Info last
	sort.Slice(allFindings, func(i, j int) bool {
		return riskSortKey(allFindings[i].RiskLevel) < riskSortKey(allFindings[j].RiskLevel)
	})

	bold := colorBold
	reset := colorReset
	if noColor {
		bold = ""
		reset = ""
	}

	header := fmt.Sprintf("%s %s %s %s %s",
		padRight("Tool", colTool),
		padRight("Credential Type", colType),
		padRight("Storage", colStorage),
		padRight("Location", colLocation),
		padRight("Risk", colRisk),
	)
	sep := strings.Repeat("-", len(header))

	fmt.Fprintln(w, sep)
	fmt.Fprintf(w, "%s%s%s\n", bold, header, reset)
	fmt.Fprintln(w, sep)

	for _, f := range allFindings {
		color := ""
		rst := ""
		if !noColor {
			color = riskColor(f.RiskLevel)
			rst = colorReset
		}

		riskStr := fmt.Sprintf("%s%s%s", color, strings.ToUpper(f.RiskLevel.String()), rst)

		line := fmt.Sprintf("%s %s %s %s %s",
			padRight(truncate(f.ToolName, colTool), colTool),
			padRight(truncate(f.CredentialType, colType), colType),
			padRight(truncate(f.StorageType.String(), colStorage), colStorage),
			padRight(truncate(f.Location, colLocation), colLocation),
			riskStr,
		)
		fmt.Fprintln(w, line)

		// Value preview on next line
		if f.ValuePreview != "" {
			fmt.Fprintf(w, "  %s Value: %s\n", strings.Repeat(" ", colTool), f.ValuePreview)
		}

		// Notes if verbose
		if verbose && len(f.Notes) > 0 {
			for _, note := range f.Notes {
				fmt.Fprintf(w, "  %s Note: %s\n", strings.Repeat(" ", colTool), note)
			}
		}

		// Permissions if verbose
		if verbose && f.FilePermissions != "" {
			desc := core.DescribePermissions(f.FilePermissions)
			owner := f.FileOwner
			if owner == "" {
				owner = "N/A"
			}
			fmt.Fprintf(w, "  %s Perms: %s (%s) Owner: %s\n",
				strings.Repeat(" ", colTool), f.FilePermissions, desc, owner)
		}

		// File modified time if verbose
		if verbose && f.FileModified != "" {
			if t, err := time.Parse(time.RFC3339, f.FileModified); err == nil {
				staleness := core.DescribeStaleness(t)
				if staleness != "" {
					fmt.Fprintf(w, "  %s Last modified: %s (%s)\n",
						strings.Repeat(" ", colTool), f.FileModified, staleness)
				} else {
					fmt.Fprintf(w, "  %s Last modified: %s\n",
						strings.Repeat(" ", colTool), f.FileModified)
				}
			} else {
				fmt.Fprintf(w, "  %s Last modified: %s\n",
					strings.Repeat(" ", colTool), f.FileModified)
			}
		}

		// Remediation if verbose
		if verbose && f.Remediation != "" {
			fixColor := ""
			fixRst := ""
			if !noColor {
				fixColor = colorLow // green
				fixRst = colorReset
			}
			fmt.Fprintf(w, "  %s %sFix: %s%s\n",
				strings.Repeat(" ", colTool), fixColor, f.Remediation, fixRst)
		}
	}

	fmt.Fprintln(w, sep)

	// Summary
	counts := make(map[core.RiskLevel]int)
	for _, f := range allFindings {
		counts[f.RiskLevel]++
	}

	parts := []string{fmt.Sprintf("%d findings", len(allFindings))}
	for _, level := range []core.RiskLevel{core.RiskCritical, core.RiskHigh, core.RiskMedium, core.RiskLow, core.RiskInfo} {
		if c, ok := counts[level]; ok && c > 0 {
			color := ""
			rst := ""
			if !noColor {
				color = riskColor(level)
				rst = colorReset
			}
			parts = append(parts, fmt.Sprintf("%s%d %s%s", color, c, strings.ToUpper(level.String()), rst))
		}
	}

	fmt.Fprintf(w, "\nSummary: %s\n", strings.Join(parts, " | "))

	if len(allErrors) > 0 && verbose {
		fmt.Fprintf(w, "\nErrors (%d):\n", len(allErrors))
		for _, e := range allErrors {
			fmt.Fprintf(w, "  - %s\n", e)
		}
	}
}
