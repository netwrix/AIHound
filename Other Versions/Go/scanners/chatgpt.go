package scanners

import (
	"encoding/json"
	"os"
	"path/filepath"

	"aihound/core"
	"aihound/remediation"
)

type chatGPTScanner struct{}

func init() {
	Register(&chatGPTScanner{})
}

func (s *chatGPTScanner) Name() string      { return "ChatGPT Desktop" }
func (s *chatGPTScanner) Slug() string       { return "chatgpt" }
func (s *chatGPTScanner) IsApplicable() bool { return true }

func (s *chatGPTScanner) Scan(showSecrets bool) core.ScanResult {
	result := core.ScanResult{ScannerName: s.Name(), Platform: core.DetectPlatform().String()}
	plat := core.DetectPlatform()

	for _, p := range s.getConfigPaths(plat) {
		s.scanConfigDir(p, &result, showSecrets)
	}

	return result
}

func (s *chatGPTScanner) getConfigPaths(plat core.Platform) []string {
	var paths []string

	switch plat {
	case core.PlatformMacOS:
		home := core.GetHome()
		paths = append(paths,
			filepath.Join(home, "Library", "Application Support", "ChatGPT"),
			filepath.Join(home, "Library", "Application Support", "com.openai.chat"),
		)

	case core.PlatformWindows:
		if appdata := core.GetAppData(); appdata != "" {
			paths = append(paths,
				filepath.Join(appdata, "OpenAI", "ChatGPT"),
				filepath.Join(appdata, "com.openai.chat"),
			)
		}

	case core.PlatformWSL:
		if appdata := core.GetAppData(); appdata != "" {
			paths = append(paths,
				filepath.Join(appdata, "OpenAI", "ChatGPT"),
				filepath.Join(appdata, "com.openai.chat"),
			)
		}
	}

	return paths
}

func (s *chatGPTScanner) scanConfigDir(basePath string, result *core.ScanResult, showSecrets bool) {
	info, err := os.Stat(basePath)
	if err != nil || !info.IsDir() {
		return
	}

	entries, err := os.ReadDir(basePath)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		path := filepath.Join(basePath, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		perms := core.GetFilePermissions(path)
		owner := core.GetFileOwner(path)

		var parsed map[string]interface{}
		if err := json.Unmarshal(data, &parsed); err != nil {
			continue
		}

		s.extractTokens(parsed, path, perms, owner, result, showSecrets)
	}
}

func (s *chatGPTScanner) extractTokens(
	data map[string]interface{}, path, perms, owner string,
	result *core.ScanResult, showSecrets bool,
) {
	tokenKeys := []string{
		"accessToken", "access_token", "token", "session_token",
		"refresh_token", "api_key", "apiKey",
	}

	for _, key := range tokenKeys {
		val, ok := data[key]
		if !ok {
			continue
		}
		value, ok := val.(string)
		if !ok || len(value) <= 8 {
			continue
		}

		storage := core.PlaintextJSON
		rawValue := ""
		if showSecrets {
			rawValue = value
		}

		var notes []string
		if mtime := core.GetFileMtimeTime(path); !mtime.IsZero() {
			notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
		}

		result.Findings = append(result.Findings, core.CredentialFinding{
			ToolName:        s.Name(),
			CredentialType:  key,
			StorageType:     storage,
			Location:        path,
			Exists:          true,
			RiskLevel:       core.AssessRisk(storage, path),
			ValuePreview:    core.MaskValue(value, showSecrets),
			RawValue:        rawValue,
			FilePermissions: perms,
			FileOwner:       owner,
			FileModified:    core.GetFileMtime(path),
			Remediation:     "Restrict file permissions on ChatGPT config directory",
			RemediationHint: remediation.HintChmod("700", filepath.Dir(path)),
			Notes:           notes,
		})
	}

	// Recurse into nested objects
	for _, val := range data {
		if nested, ok := val.(map[string]interface{}); ok {
			s.extractTokens(nested, path, perms, owner, result, showSecrets)
		}
	}
}
