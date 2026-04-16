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

var openaiSecretKeyTokens = []string{"token", "key", "secret", "api_key", "apikey", "access_key", "refresh"}

type openaiCLIScanner struct{}

func init() {
	Register(&openaiCLIScanner{})
}

func (s *openaiCLIScanner) Name() string        { return "OpenAI/Codex CLI" }
func (s *openaiCLIScanner) Slug() string         { return "openai-cli" }
func (s *openaiCLIScanner) IsApplicable() bool   { return true }

func (s *openaiCLIScanner) Scan(showSecrets bool) core.ScanResult {
	result := core.ScanResult{ScannerName: s.Name(), Platform: core.DetectPlatform().String()}
	plat := core.DetectPlatform()

	for _, p := range s.getPlaintextPaths(plat) {
		s.scanPlaintext(p, &result, showSecrets)
	}

	for _, p := range s.getJSONPaths(plat) {
		s.scanJSONFile(p, &result, showSecrets)
	}

	for _, dir := range s.getJSONDirectories(plat) {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		matches, err := filepath.Glob(filepath.Join(dir, "*.json"))
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to enumerate %s: %v", dir, err))
			continue
		}
		for _, jsonFile := range matches {
			s.scanJSONFile(jsonFile, &result, showSecrets)
		}
	}

	return result
}

func (s *openaiCLIScanner) getPlaintextPaths(plat core.Platform) []string {
	var paths []string
	home := core.GetHome()
	paths = append(paths, filepath.Join(home, ".openai", "api_key"))

	if plat == core.PlatformWSL {
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			paths = append(paths, filepath.Join(winHome, ".openai", "api_key"))
		}
		if appdata := core.GetAppData(); appdata != "" {
			paths = append(paths, filepath.Join(appdata, "OpenAI", "api_key"))
		}
	} else if plat == core.PlatformWindows {
		if appdata := core.GetAppData(); appdata != "" {
			paths = append(paths, filepath.Join(appdata, "OpenAI", "api_key"))
		}
	}
	return paths
}

func (s *openaiCLIScanner) getJSONPaths(plat core.Platform) []string {
	var paths []string
	home := core.GetHome()
	paths = append(paths, filepath.Join(home, ".openai", "auth.json"))

	if plat == core.PlatformWSL {
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			paths = append(paths, filepath.Join(winHome, ".openai", "auth.json"))
		}
		if appdata := core.GetAppData(); appdata != "" {
			paths = append(paths, filepath.Join(appdata, "OpenAI", "auth.json"))
		}
	} else if plat == core.PlatformWindows {
		if appdata := core.GetAppData(); appdata != "" {
			paths = append(paths, filepath.Join(appdata, "OpenAI", "auth.json"))
		}
	}
	return paths
}

func (s *openaiCLIScanner) getJSONDirectories(plat core.Platform) []string {
	var dirs []string
	home := core.GetHome()
	dirs = append(dirs, filepath.Join(home, ".codex"))

	if plat == core.PlatformWSL {
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			dirs = append(dirs, filepath.Join(winHome, ".codex"))
		}
		if appdata := core.GetAppData(); appdata != "" {
			dirs = append(dirs, filepath.Join(appdata, "OpenAI"))
		}
	} else if plat == core.PlatformWindows {
		if appdata := core.GetAppData(); appdata != "" {
			dirs = append(dirs, filepath.Join(appdata, "OpenAI"))
		}
	}
	return dirs
}

func (s *openaiCLIScanner) scanPlaintext(path string, result *core.ScanResult, showSecrets bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	value := strings.TrimSpace(string(data))
	if value == "" {
		return
	}

	perms := core.GetFilePermissions(path)
	owner := core.GetFileOwner(path)
	storage := core.PlaintextFile

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
		CredentialType:  "openai_api_key",
		StorageType:     storage,
		Location:        path,
		Exists:          true,
		RiskLevel:       core.AssessRisk(storage, path),
		ValuePreview:    core.MaskValue(value, showSecrets),
		RawValue:        rawValue,
		FilePermissions: perms,
		FileOwner:       owner,
		FileModified:    core.GetFileMtime(path),
		Remediation:     "Use OPENAI_API_KEY environment variable instead of plaintext file",
		RemediationHint: remediation.HintMigrateToEnv([]string{"OPENAI_API_KEY"}, path),
		Notes:           notes,
	})
}

func (s *openaiCLIScanner) scanJSONFile(path string, result *core.ScanResult, showSecrets bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}

	var data interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to parse %s: %v", path, err))
		return
	}

	perms := core.GetFilePermissions(path)
	owner := core.GetFileOwner(path)
	s.walkJSON(data, path, perms, owner, result, showSecrets, "")
}

func (s *openaiCLIScanner) walkJSON(data interface{}, path, perms, owner string, result *core.ScanResult, showSecrets bool, keyPath string) {
	storage := core.PlaintextJSON

	switch v := data.(type) {
	case map[string]interface{}:
		for k, val := range v {
			subPath := k
			if keyPath != "" {
				subPath = keyPath + "." + k
			}

			switch inner := val.(type) {
			case string:
				if inner == "" {
					continue
				}
				kLower := strings.ToLower(k)
				matched := false
				for _, tok := range openaiSecretKeyTokens {
					if strings.Contains(kLower, tok) {
						matched = true
						break
					}
				}
				if !matched || len(inner) <= 8 {
					continue
				}

				notes := []string{fmt.Sprintf("JSON key path: %s", subPath)}
				if mtime := core.GetFileMtimeTime(path); !mtime.IsZero() {
					notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
				}

				rawValue := ""
				if showSecrets {
					rawValue = inner
				}

				result.Findings = append(result.Findings, core.CredentialFinding{
					ToolName:        s.Name(),
					CredentialType:  fmt.Sprintf("openai:%s", k),
					StorageType:     storage,
					Location:        path,
					Exists:          true,
					RiskLevel:       core.AssessRisk(storage, path),
					ValuePreview:    core.MaskValue(inner, showSecrets),
					RawValue:        rawValue,
					FilePermissions: perms,
					FileOwner:       owner,
					FileModified:    core.GetFileMtime(path),
					Remediation:     "Use OPENAI_API_KEY environment variable instead of plaintext file",
					RemediationHint: remediation.HintMigrateToEnv([]string{"OPENAI_API_KEY"}, path),
					Notes:           notes,
				})
			case map[string]interface{}, []interface{}:
				s.walkJSON(inner, path, perms, owner, result, showSecrets, subPath)
			}
		}
	case []interface{}:
		for i, item := range v {
			subPath := fmt.Sprintf("%s[%d]", keyPath, i)
			switch item.(type) {
			case map[string]interface{}, []interface{}:
				s.walkJSON(item, path, perms, owner, result, showSecrets, subPath)
			}
		}
	}
}
