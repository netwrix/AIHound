package scanners

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aihound/core"
	"aihound/remediation"
)

// secretKeys are the JSON keys that indicate a credential value.
var openclawSecretKeys = []string{
	"accessToken", "access_token", "refreshToken", "refresh_token",
	"apiKey", "api_key", "token", "auth_token", "secret",
	"password", "botToken", "bot_token", "clientSecret", "client_secret",
}

// secretKeywords used for heuristic key-name matching.
var openclawSecretKeywords = []string{
	"token", "key", "secret", "password", "passwd", "auth",
	"credential", "cred", "apikey", "api_key", "accesstoken",
	"refreshtoken", "bottoken", "clientsecret",
}

type openclawScanner struct{}

func init() {
	Register(&openclawScanner{})
}

func (s *openclawScanner) Name() string      { return "OpenClaw" }
func (s *openclawScanner) Slug() string       { return "openclaw" }
func (s *openclawScanner) IsApplicable() bool { return true }

func (s *openclawScanner) Scan(showSecrets bool) core.ScanResult {
	result := core.ScanResult{ScannerName: s.Name(), Platform: core.DetectPlatform().String()}
	plat := core.DetectPlatform()

	for _, base := range s.getBasePaths(plat) {
		s.scanAuthProfiles(base, &result, showSecrets)
		s.scanCredentialsDir(base, &result, showSecrets)
		s.scanSecretsJSON(base, &result, showSecrets)
		s.scanMainConfig(base, &result, showSecrets)
		s.scanEnvFile(base, &result, showSecrets)
		s.scanLegacyOauth(base, &result, showSecrets)
	}

	return result
}

func (s *openclawScanner) getBasePaths(plat core.Platform) []string {
	home := core.GetHome()
	paths := []string{filepath.Join(home, ".openclaw")}

	if plat == core.PlatformWSL {
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			paths = append(paths, filepath.Join(winHome, ".openclaw"))
		}
	}

	return paths
}

// --- Auth Profiles (per-agent OAuth + API keys) ---

func (s *openclawScanner) scanAuthProfiles(base string, result *core.ScanResult, showSecrets bool) {
	agentsDir := filepath.Join(base, "agents")
	entries, err := os.ReadDir(agentsDir)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		authFile := filepath.Join(agentsDir, entry.Name(), "agent", "auth-profiles.json")
		data, err := os.ReadFile(authFile)
		if err != nil {
			continue
		}

		perms := core.GetFilePermissions(authFile)
		owner := core.GetFileOwner(authFile)

		var obj map[string]interface{}
		if err := json.Unmarshal(data, &obj); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to parse %s: %s", authFile, err))
			continue
		}

		s.extractSecretsRecursive(obj, authFile, perms, owner, result, showSecrets, fmt.Sprintf("agent:%s", entry.Name()), 0)
	}
}

// --- Credentials directory ---

func (s *openclawScanner) scanCredentialsDir(base string, result *core.ScanResult, showSecrets bool) {
	credsDir := filepath.Join(base, "credentials")
	if _, err := os.Stat(credsDir); err != nil {
		return
	}

	// WhatsApp credentials
	waDir := filepath.Join(credsDir, "whatsapp")
	if entries, err := os.ReadDir(waDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			credsFile := filepath.Join(waDir, entry.Name(), "creds.json")
			s.scanJSONFile(credsFile, result, showSecrets, fmt.Sprintf("whatsapp:%s", entry.Name()))
		}
	}

	// All JSON files in credentials root
	matches, _ := filepath.Glob(filepath.Join(credsDir, "*.json"))
	for _, jsonFile := range matches {
		s.scanJSONFile(jsonFile, result, showSecrets, "credentials")
	}
}

// --- secrets.json ---

func (s *openclawScanner) scanSecretsJSON(base string, result *core.ScanResult, showSecrets bool) {
	path := filepath.Join(base, "secrets.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	perms := core.GetFilePermissions(path)
	owner := core.GetFileOwner(path)

	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to parse %s: %s", path, err))
		return
	}

	s.extractSecretsRecursive(obj, path, perms, owner, result, showSecrets, "secrets.json", 0)
}

// --- Main config (openclaw.json) ---

func (s *openclawScanner) scanMainConfig(base string, result *core.ScanResult, showSecrets bool) {
	path := filepath.Join(base, "openclaw.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}

	perms := core.GetFilePermissions(path)
	owner := core.GetFileOwner(path)

	// Strip JS-style // comments
	var lines []string
	for _, line := range strings.Split(string(raw), "\n") {
		stripped := strings.TrimLeft(line, " \t")
		if strings.HasPrefix(stripped, "//") {
			continue
		}
		lines = append(lines, line)
	}

	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(strings.Join(lines, "\n")), &obj); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to parse %s: %s", path, err))
		return
	}

	// Check gateway auth token
	if gateway, ok := obj["gateway"].(map[string]interface{}); ok {
		if auth, ok := gateway["auth"].(map[string]interface{}); ok {
			if token, ok := auth["token"].(string); ok && len(token) > 8 {
				rawValue := ""
				if showSecrets {
					rawValue = token
				}
				notes := []string{"OpenClaw gateway auth token (inline)"}
				if mtime := core.GetFileMtimeTime(path); !mtime.IsZero() {
					notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
				}
				result.Findings = append(result.Findings, core.CredentialFinding{
					ToolName:        s.Name(),
					CredentialType:  "gateway_auth_token",
					StorageType:     core.PlaintextJSON,
					Location:        path,
					Exists:          true,
					RiskLevel:       core.AssessRisk(core.PlaintextJSON, path),
					ValuePreview:    core.MaskValue(token, showSecrets),
					RawValue:        rawValue,
					FilePermissions: perms,
					FileOwner:       owner,
					FileModified:    core.GetFileMtime(path),
					Remediation:     "Use SecretRef (env:, file:) instead of inline secrets",
					RemediationHint: remediation.HintManual(
						"Use SecretRef (env:, file:) instead of inline secrets",
						map[string]any{"suggested_format": "env:VAR_NAME"},
					),
					Notes:           notes,
				})
			}
		}
	}

	// Check channel configs for inline tokens
	if channels, ok := obj["channels"].(map[string]interface{}); ok {
		s.extractSecretsRecursive(channels, path, perms, owner, result, showSecrets, "channels", 0)
	}

	// Check agent model configs for API keys
	if agents, ok := obj["agents"].(map[string]interface{}); ok {
		s.extractSecretsRecursive(agents, path, perms, owner, result, showSecrets, "agents", 0)
	}
}

// --- .env file ---

func (s *openclawScanner) scanEnvFile(base string, result *core.ScanResult, showSecrets bool) {
	path := filepath.Join(base, ".env")
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}

	perms := core.GetFilePermissions(path)
	owner := core.GetFileOwner(path)
	storage := core.PlaintextENV

	secretPatterns := []string{"KEY", "TOKEN", "SECRET", "PASSWORD", "AUTH", "CREDENTIAL"}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "="); idx >= 0 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			value = strings.Trim(value, "'\"")
			if value == "" {
				continue
			}
			keyUpper := strings.ToUpper(key)
			matched := false
			for _, p := range secretPatterns {
				if strings.Contains(keyUpper, p) {
					matched = true
					break
				}
			}
			if matched {
				rawValue := ""
				if showSecrets {
					rawValue = value
				}
				notes := []string{"From OpenClaw .env file"}
				if mtime := core.GetFileMtimeTime(path); !mtime.IsZero() {
					notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
				}
				result.Findings = append(result.Findings, core.CredentialFinding{
					ToolName:        s.Name(),
					CredentialType:  fmt.Sprintf("env_file:%s", key),
					StorageType:     storage,
					Location:        path,
					Exists:          true,
					RiskLevel:       core.AssessRisk(storage, path),
					ValuePreview:    core.MaskValue(value, showSecrets),
					RawValue:        rawValue,
					FilePermissions: perms,
					FileOwner:       owner,
					FileModified:    core.GetFileMtime(path),
					Remediation:     "Use SecretRef (env:, file:) instead of inline secrets",
					RemediationHint: remediation.HintManual(
						"Use SecretRef (env:, file:) instead of inline secrets",
						map[string]any{"suggested_format": "env:VAR_NAME"},
					),
					Notes:           notes,
				})
			}
		}
	}
}

// --- Legacy oauth.json ---

func (s *openclawScanner) scanLegacyOauth(base string, result *core.ScanResult, showSecrets bool) {
	path := filepath.Join(base, "credentials", "oauth.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	perms := core.GetFilePermissions(path)
	owner := core.GetFileOwner(path)

	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return
	}

	s.extractSecretsRecursive(obj, path, perms, owner, result, showSecrets, "legacy_oauth", 0)
}

// --- Helpers ---

func (s *openclawScanner) scanJSONFile(path string, result *core.ScanResult, showSecrets bool, context string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	perms := core.GetFilePermissions(path)
	owner := core.GetFileOwner(path)

	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return
	}

	s.extractSecretsRecursive(obj, path, perms, owner, result, showSecrets, context, 0)
}

func (s *openclawScanner) extractSecretsRecursive(
	data map[string]interface{}, path, perms, owner string,
	result *core.ScanResult, showSecrets bool,
	context string, depth int,
) {
	if depth > 10 {
		return
	}

	for key, val := range data {
		switch v := val.(type) {
		case string:
			if len(v) <= 8 {
				continue
			}
			if !s.isSecretKey(key) && !s.looksLikeToken(v) {
				continue
			}

			// SecretRef detection: skip values referencing external sources
			if strings.HasPrefix(v, "env:") || strings.HasPrefix(v, "file:") || strings.HasPrefix(v, "exec:") {
				var notes []string
				if context != "" {
					notes = append(notes, fmt.Sprintf("Context: %s", context))
				}
				notes = append(notes, "SecretRef (not inline — references external source)")
				if mtime := core.GetFileMtimeTime(path); !mtime.IsZero() {
					notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
				}
				result.Findings = append(result.Findings, core.CredentialFinding{
					ToolName:       s.Name(),
					CredentialType: fmt.Sprintf("secret_ref:%s", key),
					StorageType:    core.PlaintextJSON,
					Location:       path,
					Exists:         true,
					RiskLevel:      core.RiskInfo,
					ValuePreview:   v,
					FileModified:   core.GetFileMtime(path),
					Notes:          notes,
				})
				continue
			}

			storage := core.PlaintextJSON
			var notes []string
			if context != "" {
				notes = append(notes, fmt.Sprintf("Context: %s", context))
			}
			notes = append(notes, "Plaintext credential in OpenClaw config")
			if mtime := core.GetFileMtimeTime(path); !mtime.IsZero() {
				notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
			}

			rawValue := ""
			if showSecrets {
				rawValue = v
			}
			result.Findings = append(result.Findings, core.CredentialFinding{
				ToolName:        s.Name(),
				CredentialType:  key,
				StorageType:     storage,
				Location:        path,
				Exists:          true,
				RiskLevel:       core.AssessRisk(storage, path),
				ValuePreview:    core.MaskValue(v, showSecrets),
				RawValue:        rawValue,
				FilePermissions: perms,
				FileOwner:       owner,
				FileModified:    core.GetFileMtime(path),
				Remediation:     "Use SecretRef (env:, file:) instead of inline secrets",
				RemediationHint: remediation.HintManual(
					"Use SecretRef (env:, file:) instead of inline secrets",
					map[string]any{"suggested_format": "env:VAR_NAME"},
				),
				Notes:           notes,
			})

		case map[string]interface{}:
			s.extractSecretsRecursive(v, path, perms, owner, result, showSecrets, context, depth+1)

		case []interface{}:
			for _, item := range v {
				if m, ok := item.(map[string]interface{}); ok {
					s.extractSecretsRecursive(m, path, perms, owner, result, showSecrets, context, depth+1)
				}
			}
		}
	}
}

func (s *openclawScanner) isSecretKey(key string) bool {
	keyLower := strings.ToLower(key)
	for _, kw := range openclawSecretKeywords {
		if strings.Contains(keyLower, kw) {
			return true
		}
	}
	return false
}

func (s *openclawScanner) looksLikeToken(value string) bool {
	if len(value) < 20 {
		return false
	}
	for _, prefix := range []string{"/", "http://", "https://", "env:", "file:", "exec:"} {
		if strings.HasPrefix(value, prefix) {
			return false
		}
	}
	alphanumCount := 0
	for _, c := range value {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			alphanumCount++
		}
	}
	return float64(alphanumCount)/float64(len(value)) > 0.8
}
