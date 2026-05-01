package scanners

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"aihound/core"
)

type claudeCodeScanner struct{}

func init() {
	Register(&claudeCodeScanner{})
}

func (s *claudeCodeScanner) Name() string  { return "Claude Code CLI" }
func (s *claudeCodeScanner) Slug() string  { return "claude-code" }
func (s *claudeCodeScanner) IsApplicable() bool { return true }

func (s *claudeCodeScanner) Scan(showSecrets bool) core.ScanResult {
	result := core.ScanResult{ScannerName: s.Name(), Platform: core.DetectPlatform().String()}
	plat := core.DetectPlatform()
	home := core.GetHome()

	// Credential paths
	credPaths := []string{
		filepath.Join(home, ".claude", ".credentials.json"),
	}
	if plat == core.PlatformWSL {
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			credPaths = append(credPaths, filepath.Join(winHome, ".claude", ".credentials.json"))
		}
	}

	// Config paths: primary files first, then backups
	var primaryPaths, backupPaths []string
	primaryPaths = append(primaryPaths,
		filepath.Join(home, ".claude.json"),
		filepath.Join(home, ".claude", "settings.json"),
	)
	backupPaths = append(backupPaths, s.collectBackups(filepath.Join(home, ".claude", "backups"))...)

	if plat == core.PlatformWSL {
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			primaryPaths = append(primaryPaths,
				filepath.Join(winHome, ".claude.json"),
				filepath.Join(winHome, ".claude", "settings.json"),
			)
			backupPaths = append(backupPaths, s.collectBackups(filepath.Join(winHome, ".claude", "backups"))...)
		}
	}

	for _, p := range credPaths {
		s.scanCredentialsFile(p, &result, showSecrets)
	}

	// Scan config files with cross-file dedup
	seen := make(map[string]bool)
	for _, p := range primaryPaths {
		findings := core.ParseMCPFileDedup(p, s.Name(), showSecrets, seen)
		result.Findings = append(result.Findings, findings...)
	}

	// Count existing backup files, scan them (dedup suppresses duplicates)
	backupCount := 0
	for _, p := range backupPaths {
		if _, err := os.Stat(p); err == nil {
			backupCount++
		}
	}
	for _, p := range backupPaths {
		findings := core.ParseMCPFileDedup(p, s.Name(), showSecrets, seen)
		result.Findings = append(result.Findings, findings...)
	}

	// Add backup exposure note to primary MCP findings
	if backupCount > 0 {
		for i := range result.Findings {
			f := &result.Findings[i]
			if strings.HasPrefix(f.CredentialType, "mcp_env:") && !strings.Contains(f.Location, ".backup") {
				f.Notes = append(f.Notes, fmt.Sprintf("Also present in %d backup file(s) under ~/.claude/backups/", backupCount))
			}
		}
	}

	return result
}

func (s *claudeCodeScanner) scanCredentialsFile(path string, result *core.ScanResult, showSecrets bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	perms := core.GetFilePermissions(path)
	owner := core.GetFileOwner(path)

	// Try as object first
	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err == nil {
		s.extractAuthEntries(obj, path, perms, owner, result, showSecrets)
		return
	}

	// Try as array
	var arr []interface{}
	if err := json.Unmarshal(data, &arr); err == nil {
		for _, item := range arr {
			if m, ok := item.(map[string]interface{}); ok {
				s.extractAuthEntries(m, path, perms, owner, result, showSecrets)
			}
		}
		return
	}

	result.Errors = append(result.Errors, fmt.Sprintf("Failed to parse %s", path))
}

// tokenField maps a JSON key to its credential type label.
type tokenField struct {
	jsonKey  string
	credType string
}

var claudeCodeTokenFields = []tokenField{
	{"access", "oauth_access_token"},
	{"accessToken", "oauth_access_token"},
	{"refresh", "oauth_refresh_token"},
	{"refreshToken", "oauth_refresh_token"},
	{"apiKey", "api_key"},
	{"token", "auth_token"},
}

func (s *claudeCodeScanner) extractAuthEntries(
	data map[string]interface{}, path, perms, owner string,
	result *core.ScanResult, showSecrets bool,
) {
	storage := core.PlaintextJSON
	risk := core.AssessRisk(storage, path)

	// Track which keys are token fields so we skip them during recursion
	tokenKeys := make(map[string]bool)
	for _, tf := range claudeCodeTokenFields {
		tokenKeys[tf.jsonKey] = true
	}

	for _, tf := range claudeCodeTokenFields {
		val, ok := data[tf.jsonKey]
		if !ok {
			continue
		}
		value, ok := val.(string)
		if !ok || value == "" {
			continue
		}

		var notes []string

		// Auth type
		if authType, ok := data["type"].(string); ok && authType != "" {
			notes = append(notes, fmt.Sprintf("Auth type: %s", authType))
		}

		// Expiry
		var expiryStr string
		expiresVal := data["expires"]
		if expiresVal == nil {
			expiresVal = data["expiresAt"]
		}
		if expiresVal != nil {
			if num, ok := expiresVal.(float64); ok {
				var t time.Time
				if num > 1e12 {
					t = time.UnixMilli(int64(num))
				} else {
					t = time.Unix(int64(num), 0)
				}
				expiryStr = t.UTC().Format(time.RFC3339)
				notes = append(notes, fmt.Sprintf("Expires: %s", t.UTC().Format("2006-01-02 15:04 UTC")))
			}
		}

		rawValue := ""
		if showSecrets {
			rawValue = value
		}

		if mtime := core.GetFileMtimeTime(path); !mtime.IsZero() {
			notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
		}

		result.Findings = append(result.Findings, core.CredentialFinding{
			ToolName:        s.Name(),
			CredentialType:  tf.credType,
			StorageType:     storage,
			Location:        path,
			Exists:          true,
			RiskLevel:       risk,
			ValuePreview:    core.MaskValue(value, showSecrets),
			RawValue:        rawValue,
			FilePermissions: perms,
			FileOwner:       owner,
			Expiry:          expiryStr,
			FileModified:    core.GetFileMtime(path),
			Remediation:     chmodRemediation(path),
			RemediationHint: chmodRemediationHint(path),
			Notes:           notes,
		})
	}

	// Recurse into nested dicts
	for key, val := range data {
		if tokenKeys[key] {
			continue
		}
		if nested, ok := val.(map[string]interface{}); ok {
			s.extractAuthEntries(nested, path, perms, owner, result, showSecrets)
		}
	}
}

// collectBackups returns paths to .claude.json backup files in a directory.
func (s *claudeCodeScanner) collectBackups(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var paths []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".claude.json.backup") {
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
	}
	return paths
}
