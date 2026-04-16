package scanners

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"aihound/core"
	"aihound/remediation"
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

	// Config paths (MCP)
	configPaths := []string{
		filepath.Join(home, ".claude.json"),
		filepath.Join(home, ".claude", "settings.json"),
	}
	if plat == core.PlatformWSL {
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			configPaths = append(configPaths,
				filepath.Join(winHome, ".claude.json"),
				filepath.Join(winHome, ".claude", "settings.json"),
			)
		}
	}

	for _, p := range credPaths {
		s.scanCredentialsFile(p, &result, showSecrets)
	}
	for _, p := range configPaths {
		findings := core.ParseMCPFile(p, s.Name(), showSecrets)
		result.Findings = append(result.Findings, findings...)
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
			Remediation:     "Restrict file permissions: chmod 600 " + path,
			RemediationHint: remediation.HintChmod("600", path),
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
