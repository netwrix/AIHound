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

var mlSecretKeyTokens = []string{"token", "key", "secret", "api_key", "apikey", "access_key"}

type mlPlatformBundle struct {
	label      string
	plainPaths []string
	jsonPaths  []string
}

type mlPlatformsScanner struct{}

func init() {
	Register(&mlPlatformsScanner{})
}

func (s *mlPlatformsScanner) Name() string        { return "ML Platforms (Replicate/Together/Groq)" }
func (s *mlPlatformsScanner) Slug() string         { return "ml-platforms" }
func (s *mlPlatformsScanner) IsApplicable() bool   { return true }

func (s *mlPlatformsScanner) Scan(showSecrets bool) core.ScanResult {
	result := core.ScanResult{ScannerName: s.Name(), Platform: core.DetectPlatform().String()}
	plat := core.DetectPlatform()

	for _, bundle := range s.buildAllPaths(plat) {
		for _, p := range bundle.plainPaths {
			s.scanPlaintext(p, bundle.label, &result, showSecrets)
		}
		for _, p := range bundle.jsonPaths {
			s.scanJSON(p, bundle.label, &result, showSecrets)
		}
	}

	return result
}

func (s *mlPlatformsScanner) buildAllPaths(plat core.Platform) []mlPlatformBundle {
	home := core.GetHome()
	var winHome, appdata string
	if plat == core.PlatformWSL {
		winHome = core.GetWSLWindowsHome()
		appdata = core.GetAppData()
	} else if plat == core.PlatformWindows {
		appdata = core.GetAppData()
	}

	// Replicate
	replicate := mlPlatformBundle{
		label:      "replicate",
		plainPaths: []string{filepath.Join(home, ".replicate", "auth")},
		jsonPaths:  []string{filepath.Join(home, ".replicate", "config.json")},
	}
	if winHome != "" {
		replicate.plainPaths = append(replicate.plainPaths, filepath.Join(winHome, ".replicate", "auth"))
		replicate.jsonPaths = append(replicate.jsonPaths, filepath.Join(winHome, ".replicate", "config.json"))
	}
	if appdata != "" {
		replicate.jsonPaths = append(replicate.jsonPaths, filepath.Join(appdata, "replicate", "config.json"))
	}

	// Together
	together := mlPlatformBundle{
		label:      "together",
		plainPaths: []string{filepath.Join(home, ".together", "api_key")},
		jsonPaths:  []string{filepath.Join(home, ".together", "config.json")},
	}
	if winHome != "" {
		together.plainPaths = append(together.plainPaths, filepath.Join(winHome, ".together", "api_key"))
		together.jsonPaths = append(together.jsonPaths, filepath.Join(winHome, ".together", "config.json"))
	}
	if appdata != "" {
		together.jsonPaths = append(together.jsonPaths, filepath.Join(appdata, "together", "config.json"))
	}

	// Groq
	groq := mlPlatformBundle{
		label:      "groq",
		plainPaths: []string{filepath.Join(home, ".groq", "api_key")},
		jsonPaths:  []string{filepath.Join(home, ".groq", "config.json")},
	}
	if winHome != "" {
		groq.plainPaths = append(groq.plainPaths, filepath.Join(winHome, ".groq", "api_key"))
		groq.jsonPaths = append(groq.jsonPaths, filepath.Join(winHome, ".groq", "config.json"))
	}
	if appdata != "" {
		groq.jsonPaths = append(groq.jsonPaths, filepath.Join(appdata, "groq", "config.json"))
	}

	return []mlPlatformBundle{replicate, together, groq}
}

func (s *mlPlatformsScanner) remediationFor(label string) string {
	return "Use environment variables (REPLICATE_API_TOKEN, TOGETHER_API_KEY, GROQ_API_KEY) instead of config files"
}

func (s *mlPlatformsScanner) scanPlaintext(path, label string, result *core.ScanResult, showSecrets bool) {
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

	notes := []string{fmt.Sprintf("Platform: %s", label)}
	if mtime := core.GetFileMtimeTime(path); !mtime.IsZero() {
		notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
	}

	rawValue := ""
	if showSecrets {
		rawValue = value
	}

	result.Findings = append(result.Findings, core.CredentialFinding{
		ToolName:        s.Name(),
		CredentialType:  fmt.Sprintf("%s_api_key", label),
		StorageType:     storage,
		Location:        path,
		Exists:          true,
		RiskLevel:       core.AssessRisk(storage, path),
		ValuePreview:    core.MaskValue(value, showSecrets),
		RawValue:        rawValue,
		FilePermissions: perms,
		FileOwner:       owner,
		FileModified:    core.GetFileMtime(path),
		Remediation:     s.remediationFor(label),
		RemediationHint: remediation.HintMigrateToEnv([]string{"REPLICATE_API_TOKEN", "TOGETHER_API_KEY", "GROQ_API_KEY"}, path),
		Notes:           notes,
	})
}

func (s *mlPlatformsScanner) scanJSON(path, label string, result *core.ScanResult, showSecrets bool) {
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
	s.walkJSON(data, path, label, perms, owner, result, showSecrets, "")
}

func (s *mlPlatformsScanner) walkJSON(data interface{}, path, label, perms, owner string, result *core.ScanResult, showSecrets bool, keyPath string) {
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
				for _, tok := range mlSecretKeyTokens {
					if strings.Contains(kLower, tok) {
						matched = true
						break
					}
				}
				if !matched || len(inner) <= 8 {
					continue
				}

				notes := []string{
					fmt.Sprintf("Platform: %s", label),
					fmt.Sprintf("JSON key path: %s", subPath),
				}
				if mtime := core.GetFileMtimeTime(path); !mtime.IsZero() {
					notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
				}

				rawValue := ""
				if showSecrets {
					rawValue = inner
				}

				result.Findings = append(result.Findings, core.CredentialFinding{
					ToolName:        s.Name(),
					CredentialType:  fmt.Sprintf("%s:%s", label, k),
					StorageType:     storage,
					Location:        path,
					Exists:          true,
					RiskLevel:       core.AssessRisk(storage, path),
					ValuePreview:    core.MaskValue(inner, showSecrets),
					RawValue:        rawValue,
					FilePermissions: perms,
					FileOwner:       owner,
					FileModified:    core.GetFileMtime(path),
					Remediation:     s.remediationFor(label),
					RemediationHint: remediation.HintMigrateToEnv([]string{"REPLICATE_API_TOKEN", "TOGETHER_API_KEY", "GROQ_API_KEY"}, path),
					Notes:           notes,
				})
			case map[string]interface{}, []interface{}:
				s.walkJSON(inner, path, label, perms, owner, result, showSecrets, subPath)
			}
		}
	case []interface{}:
		for i, item := range v {
			subPath := fmt.Sprintf("%s[%d]", keyPath, i)
			switch item.(type) {
			case map[string]interface{}, []interface{}:
				s.walkJSON(item, path, label, perms, owner, result, showSecrets, subPath)
			}
		}
	}
}
