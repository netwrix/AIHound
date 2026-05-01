package output

import (
	"encoding/json"
	"io"
	"os"
	"runtime"
	"time"

	"aihound/core"
)

// JSONReport is the top-level structure for JSON output.
type JSONReport struct {
	ScanMetadata struct {
		Timestamp      string `json:"timestamp"`
		Platform       string `json:"platform"`
		AihoundVersion string `json:"aihound_version"`
	} `json:"scan_metadata"`
	Findings []JSONFinding `json:"findings"`
	Errors   []string      `json:"errors"`
	Summary  struct {
		TotalFindings int            `json:"total_findings"`
		ByRisk        map[string]int `json:"by_risk"`
	} `json:"summary"`
}

// JSONFinding represents a single credential finding in JSON output.
// RawValue is intentionally excluded.
type JSONFinding struct {
	ToolName        string         `json:"tool_name"`
	CredentialType  string         `json:"credential_type"`
	StorageType     string         `json:"storage_type"`
	Location        string         `json:"location"`
	Exists          bool           `json:"exists"`
	RiskLevel       string         `json:"risk_level"`
	ValuePreview    string         `json:"value_preview,omitempty"`
	FilePermissions string         `json:"file_permissions,omitempty"`
	FileOwner       string         `json:"file_owner,omitempty"`
	Expiry          string         `json:"expiry,omitempty"`
	FileModified    string         `json:"file_modified,omitempty"`
	Remediation     string         `json:"remediation,omitempty"`
	RemediationHint map[string]any `json:"remediation_hint,omitempty"`
	Notes           []string       `json:"notes,omitempty"`
}

func buildReport(results []core.ScanResult, version string) JSONReport {
	var report JSONReport

	// Metadata
	report.ScanMetadata.Timestamp = time.Now().UTC().Format(time.RFC3339)
	report.ScanMetadata.AihoundVersion = version

	// Determine platform from results, fallback to runtime.GOOS
	platform := runtime.GOOS
	if len(results) > 0 && results[0].Platform != "" {
		platform = results[0].Platform
	}
	report.ScanMetadata.Platform = platform

	// Collect findings and errors
	report.Findings = []JSONFinding{}
	report.Errors = []string{}
	counts := make(map[string]int)

	for _, r := range results {
		for _, f := range r.Findings {
			jf := JSONFinding{
				ToolName:        f.ToolName,
				CredentialType:  f.CredentialType,
				StorageType:     f.StorageType.String(),
				Location:        f.Location,
				Exists:          f.Exists,
				RiskLevel:       f.RiskLevel.String(),
				ValuePreview:    f.ValuePreview,
				FilePermissions: f.FilePermissions,
				FileOwner:       f.FileOwner,
				Expiry:          f.Expiry,
				FileModified:    f.FileModified,
				Remediation:     f.Remediation,
				RemediationHint: f.RemediationHint,
				Notes:           f.Notes,
			}
			report.Findings = append(report.Findings, jf)
			counts[f.RiskLevel.String()]++
		}
		report.Errors = append(report.Errors, r.Errors...)
	}

	report.Summary.TotalFindings = len(report.Findings)

	// Ensure all risk levels appear in by_risk
	report.Summary.ByRisk = map[string]int{
		"critical": counts["critical"],
		"high":     counts["high"],
		"medium":   counts["medium"],
		"low":      counts["low"],
		"info":     counts["info"],
	}

	return report
}

// WriteJSON writes a JSON report to the given writer.
func WriteJSON(w io.Writer, results []core.ScanResult, version string) error {
	report := buildReport(results, version)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// WriteJSONFile writes a JSON report to a file.
// Expands ~ in the path and auto-creates parent directories.
func WriteJSONFile(path string, results []core.ScanResult, version string) error {
	resolved, err := prepareOutputPath(path)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(resolved, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return WriteJSON(f, results, version)
}
