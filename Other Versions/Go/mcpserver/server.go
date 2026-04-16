// Package mcpserver implements AIHound's Model Context Protocol server.
//
// Mirrors the Python aihound.mcp_server module: same 4 tools, 2 resources,
// 30-second scan cache, never exposes raw credential values.
//
// Built on the official github.com/modelcontextprotocol/go-sdk.
package mcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"aihound/core"
	"aihound/scanners"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// CacheTTL bounds repeat scans within a single client session. Repeat
// aihound_scan calls within this window return cached results.
const CacheTTL = 30 * time.Second

type cachedScan struct {
	timestamp time.Time
	results   []core.ScanResult
}

var (
	cacheMu sync.Mutex
	cache   = map[string]cachedScan{}
)

// ============================================================================
// Serialization — the boundary that keeps RawValue out of MCP responses
// ============================================================================

// findingID is a stable opaque identifier for a finding, used by
// aihound_get_remediation to look up findings across cached scans.
func findingID(f core.CredentialFinding) string {
	raw := f.ToolName + "|" + f.CredentialType + "|" + f.Location
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])[:16]
}

// findingToMCP converts a finding to its MCP response shape. RawValue is
// unconditionally excluded — this is the security boundary.
func findingToMCP(f core.CredentialFinding) map[string]any {
	d := map[string]any{
		"finding_id":      findingID(f),
		"tool_name":       f.ToolName,
		"credential_type": f.CredentialType,
		"storage_type":    f.StorageType.String(),
		"location":        f.Location,
		"exists":          f.Exists,
		"risk_level":      f.RiskLevel.String(),
	}
	// Optional fields — omit when empty so the JSON stays clean
	if f.ValuePreview != "" {
		d["value_preview"] = f.ValuePreview
	}
	if f.FilePermissions != "" {
		d["file_permissions"] = f.FilePermissions
	}
	if f.FileOwner != "" {
		d["file_owner"] = f.FileOwner
	}
	if f.Expiry != "" {
		d["expiry"] = f.Expiry
	}
	if f.FileModified != "" {
		d["file_modified"] = f.FileModified
	}
	if f.Remediation != "" {
		d["remediation"] = f.Remediation
	}
	if f.RemediationHint != nil {
		d["remediation_hint"] = f.RemediationHint
	}
	if len(f.Notes) > 0 {
		d["notes"] = f.Notes
	}
	// RawValue is intentionally never included.
	return d
}

// resultsToMCP wraps findings in the standard scan_metadata + summary envelope.
func resultsToMCP(results []core.ScanResult, version string) map[string]any {
	findings := make([]map[string]any, 0)
	errs := make([]string, 0)
	counts := map[string]int{
		"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0,
	}

	for _, r := range results {
		for _, f := range r.Findings {
			findings = append(findings, findingToMCP(f))
			counts[f.RiskLevel.String()]++
		}
		for _, e := range r.Errors {
			errs = append(errs, fmt.Sprintf("[%s] %s", r.ScannerName, e))
		}
	}

	platform := runtime.GOOS
	if len(results) > 0 && results[0].Platform != "" {
		platform = results[0].Platform
	}

	return map[string]any{
		"scan_metadata": map[string]any{
			"timestamp":        time.Now().UTC().Format(time.RFC3339),
			"platform":         platform,
			"aihound_version":  version,
		},
		"findings": findings,
		"errors":   errs,
		"summary": map[string]any{
			"total_findings": len(findings),
			"by_risk":        counts,
		},
	}
}

// ============================================================================
// Scanning helpers
// ============================================================================

var riskOrder = map[core.RiskLevel]int{
	core.RiskInfo:     0,
	core.RiskLow:      1,
	core.RiskMedium:   2,
	core.RiskHigh:     3,
	core.RiskCritical: 4,
}

func parseRisk(value string) (core.RiskLevel, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return core.RiskInfo, false // not specified
	case "critical":
		return core.RiskCritical, true
	case "high":
		return core.RiskHigh, true
	case "medium":
		return core.RiskMedium, true
	case "low":
		return core.RiskLow, true
	case "info":
		return core.RiskInfo, true
	}
	return core.RiskInfo, false
}

// filterByRisk drops findings below the threshold. Returns a new slice — does
// not mutate the input.
func filterByRisk(results []core.ScanResult, minRisk core.RiskLevel) []core.ScanResult {
	threshold := riskOrder[minRisk]
	out := make([]core.ScanResult, 0, len(results))
	for _, r := range results {
		kept := make([]core.CredentialFinding, 0, len(r.Findings))
		for _, f := range r.Findings {
			if riskOrder[f.RiskLevel] >= threshold {
				kept = append(kept, f)
			}
		}
		out = append(out, core.ScanResult{
			ScannerName: r.ScannerName,
			Platform:    r.Platform,
			Findings:    kept,
			Errors:      r.Errors,
			ScanTime:    r.ScanTime,
		})
	}
	return out
}

// runScan executes the requested scanners (or all applicable, if tools is nil),
// caching the result for CacheTTL seconds keyed by the sorted tool list.
func runScan(tools []string, force bool) []core.ScanResult {
	cacheKey := ""
	if len(tools) > 0 {
		sorted := append([]string{}, tools...)
		sort.Strings(sorted)
		cacheKey = strings.Join(sorted, ",")
	}

	cacheMu.Lock()
	if !force {
		if entry, ok := cache[cacheKey]; ok && time.Since(entry.timestamp) < CacheTTL {
			cacheMu.Unlock()
			return entry.results
		}
	}
	cacheMu.Unlock()

	all := scanners.GetAll()
	var selected []core.Scanner
	if len(tools) > 0 {
		want := map[string]bool{}
		for _, t := range tools {
			want[t] = true
		}
		for _, s := range all {
			if want[s.Slug()] && s.IsApplicable() {
				selected = append(selected, s)
			}
		}
	} else {
		for _, s := range all {
			if s.IsApplicable() {
				selected = append(selected, s)
			}
		}
	}

	results := make([]core.ScanResult, 0, len(selected))
	for _, s := range selected {
		// Wrap each scanner in a panic-recovery guard — one bad scanner shouldn't
		// kill the cycle (mirrors Python's BaseScanner.run()).
		var r core.ScanResult
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					r = core.ScanResult{
						ScannerName: s.Name(),
						Platform:    core.DetectPlatform().String(),
						Errors:      []string{fmt.Sprintf("panic: %v", rec)},
					}
				}
			}()
			start := time.Now()
			r = s.Scan(false) // never pass showSecrets=true; MCP never exposes raw values
			r.ScanTime = time.Since(start).Seconds()
		}()
		results = append(results, r)
	}

	cacheMu.Lock()
	cache[cacheKey] = cachedScan{timestamp: time.Now(), results: results}
	cacheMu.Unlock()

	return results
}

// findByID searches every cached scan for a finding with the given opaque ID.
func findByID(id string) (core.CredentialFinding, bool) {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	for _, entry := range cache {
		for _, r := range entry.results {
			for _, f := range r.Findings {
				if findingID(f) == id {
					return f, true
				}
			}
		}
	}
	return core.CredentialFinding{}, false
}

// ============================================================================
// Tool input/output schemas
// ============================================================================

type scanInput struct {
	Tools   []string `json:"tools,omitempty" jsonschema:"Optional list of scanner slugs (use aihound_list_scanners to enumerate). Omit to run all applicable scanners."`
	MinRisk string   `json:"min_risk,omitempty" jsonschema:"Optional minimum risk level: critical|high|medium|low|info. Findings below this are dropped."`
	Force   bool     `json:"force,omitempty" jsonschema:"If true, bypass the 30-second scan cache and re-run scanners."`
}

type listScannersInput struct{}

type getRemediationInput struct {
	FindingID string `json:"finding_id" jsonschema:"Opaque 16-char ID returned by a previous aihound_scan call."`
}

type checkInput struct {
	Tool           string `json:"tool" jsonschema:"Scanner slug to run (e.g. claude-code). Use aihound_list_scanners for valid slugs."`
	CredentialType string `json:"credential_type,omitempty" jsonschema:"Optional filter — only return findings of this credential type."`
}

// ============================================================================
// Server entry point
// ============================================================================

// Run starts the AIHound MCP server on stdio and blocks until the client
// disconnects or ctx is canceled.
func Run(ctx context.Context, version string) error {
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "aihound",
		Version: version,
	}, nil)

	// --- Tool: aihound_scan ---
	mcp.AddTool(server, &mcp.Tool{
		Name: "aihound_scan",
		Description: "Run AIHound's credential scanners and return structured findings. " +
			"Findings never contain raw credential values — only masked previews plus a " +
			"`remediation_hint` dict an agent can act on.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in scanInput) (*mcp.CallToolResult, any, error) {
		results := runScan(in.Tools, in.Force)
		if minRisk, ok := parseRisk(in.MinRisk); ok {
			results = filterByRisk(results, minRisk)
		}
		out := resultsToMCP(results, version)
		return jsonResult(out), nil, nil
	})

	// --- Tool: aihound_list_scanners ---
	mcp.AddTool(server, &mcp.Tool{
		Name:        "aihound_list_scanners",
		Description: "List all available AIHound scanners and whether they apply to this host.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, _ listScannersInput) (*mcp.CallToolResult, any, error) {
		all := scanners.GetAll()
		items := make([]map[string]any, 0, len(all))
		for _, s := range all {
			items = append(items, map[string]any{
				"slug":       s.Slug(),
				"name":       s.Name(),
				"applicable": s.IsApplicable(),
			})
		}
		return jsonResult(map[string]any{
			"scanners": items,
			"total":    len(items),
		}), nil, nil
	})

	// --- Tool: aihound_get_remediation ---
	mcp.AddTool(server, &mcp.Tool{
		Name: "aihound_get_remediation",
		Description: "Fetch remediation guidance for a finding by its opaque finding_id. " +
			"Call aihound_scan first to get IDs. Returns the human-readable remediation " +
			"string plus the structured remediation_hint dict.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in getRemediationInput) (*mcp.CallToolResult, any, error) {
		f, ok := findByID(in.FindingID)
		if !ok {
			return jsonResult(map[string]any{
				"error": fmt.Sprintf("No finding with id %s in cache. Call aihound_scan first or use force=true to refresh.", in.FindingID),
			}), nil, nil
		}
		return jsonResult(map[string]any{
			"finding_id":       in.FindingID,
			"tool_name":        f.ToolName,
			"credential_type":  f.CredentialType,
			"location":         f.Location,
			"risk_level":       f.RiskLevel.String(),
			"remediation":      f.Remediation,
			"remediation_hint": f.RemediationHint,
		}), nil, nil
	})

	// --- Tool: aihound_check ---
	mcp.AddTool(server, &mcp.Tool{
		Name: "aihound_check",
		Description: "Run a single scanner. Useful when the AI only needs to check one tool. " +
			"Bypasses the scan cache — always runs fresh.",
	}, func(_ context.Context, _ *mcp.CallToolRequest, in checkInput) (*mcp.CallToolResult, any, error) {
		results := runScan([]string{in.Tool}, true)
		if in.CredentialType != "" {
			for i, r := range results {
				kept := r.Findings[:0]
				for _, f := range r.Findings {
					if f.CredentialType == in.CredentialType {
						kept = append(kept, f)
					}
				}
				results[i].Findings = kept
			}
		}
		return jsonResult(resultsToMCP(results, version)), nil, nil
	})

	// --- Resource: aihound://findings/latest ---
	server.AddResource(&mcp.Resource{
		URI:         "aihound://findings/latest",
		Name:        "latest_findings",
		Description: "Most recent cached scan as JSON. Triggers a fresh scan if the cache is empty.",
		MIMEType:    "application/json",
	}, func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		results := runScan(nil, false)
		body, _ := json.MarshalIndent(resultsToMCP(results, version), "", "  ")
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{{
				URI:      req.Params.URI,
				MIMEType: "application/json",
				Text:     string(body),
			}},
		}, nil
	})

	// --- Resource: aihound://platform ---
	server.AddResource(&mcp.Resource{
		URI:         "aihound://platform",
		Name:        "platform",
		Description: "Detected OS, WSL status, and AIHound version. Useful for tailoring advice.",
		MIMEType:    "application/json",
	}, func(_ context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		plat := core.DetectPlatform()
		body, _ := json.MarshalIndent(map[string]any{
			"os":              plat.String(),
			"is_wsl":          plat == core.PlatformWSL,
			"aihound_version": version,
		}, "", "  ")
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{{
				URI:      req.Params.URI,
				MIMEType: "application/json",
				Text:     string(body),
			}},
		}, nil
	})

	// Run on stdio transport — blocks until the client disconnects
	return server.Run(ctx, &mcp.StdioTransport{})
}

// jsonResult serializes any value as JSON text content for a CallToolResult.
// MCP tool results are content arrays; we always emit one TextContent block
// containing pretty-printed JSON so AI clients can either parse it or display it.
func jsonResult(v any) *mcp.CallToolResult {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("serialization error: %v", err)}},
			IsError: true,
		}
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(body)}},
	}
}
