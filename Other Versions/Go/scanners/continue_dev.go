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

type continueDevScanner struct{}

func init() {
	Register(&continueDevScanner{})
}

func (s *continueDevScanner) Name() string      { return "Continue.dev" }
func (s *continueDevScanner) Slug() string       { return "continue-dev" }
func (s *continueDevScanner) IsApplicable() bool { return true }

func (s *continueDevScanner) Scan(showSecrets bool) core.ScanResult {
	result := core.ScanResult{ScannerName: s.Name(), Platform: core.DetectPlatform().String()}
	plat := core.DetectPlatform()

	for _, p := range s.getConfigPaths(plat) {
		s.scanConfig(p, &result, showSecrets)
	}

	return result
}

func (s *continueDevScanner) getConfigPaths(plat core.Platform) []string {
	var paths []string
	home := core.GetHome()

	paths = append(paths,
		filepath.Join(home, ".continue", "config.json"),
		filepath.Join(home, ".continue", "config.yaml"),
	)

	if plat == core.PlatformWSL {
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			paths = append(paths,
				filepath.Join(winHome, ".continue", "config.json"),
				filepath.Join(winHome, ".continue", "config.yaml"),
			)
		}
	}

	return paths
}

func (s *continueDevScanner) scanConfig(path string, result *core.ScanResult, showSecrets bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	perms := core.GetFilePermissions(path)
	owner := core.GetFileOwner(path)

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to parse %s: %s", path, err))
		return
	}

	// Check models array for API keys
	if modelsRaw, ok := parsed["models"]; ok {
		if models, ok := modelsRaw.([]interface{}); ok {
			for _, modelRaw := range models {
				model, ok := modelRaw.(map[string]interface{})
				if !ok {
					continue
				}
				apiKeyRaw, ok := model["apiKey"]
				if !ok {
					continue
				}
				apiKey, ok := apiKeyRaw.(string)
				if !ok || apiKey == "" {
					continue
				}

				provider := "unknown"
				if p, ok := model["provider"].(string); ok {
					provider = p
				}

				isEnvRef := strings.Contains(apiKey, "${")
				if isEnvRef {
					notes := []string{"References env var (not inline)"}
					if mtime := core.GetFileMtimeTime(path); !mtime.IsZero() {
						notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
					}
					result.Findings = append(result.Findings, core.CredentialFinding{
						ToolName:        s.Name(),
						CredentialType:  fmt.Sprintf("api_key (%s)", provider),
						StorageType:     core.PlaintextJSON,
						Location:        path,
						Exists:          true,
						RiskLevel:       core.RiskInfo,
						ValuePreview:    apiKey,
						FilePermissions: perms,
						FileOwner:       owner,
						FileModified:    core.GetFileMtime(path),
						Remediation:     "Use environment variables instead of inline API keys in config",
						Notes:           notes,
					})
				} else {
					rawValue := ""
					if showSecrets {
						rawValue = apiKey
					}
					notes := []string{"PLAINTEXT API key in config!"}
					if mtime := core.GetFileMtimeTime(path); !mtime.IsZero() {
						notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
					}
					result.Findings = append(result.Findings, core.CredentialFinding{
						ToolName:        s.Name(),
						CredentialType:  fmt.Sprintf("api_key (%s)", provider),
						StorageType:     core.PlaintextJSON,
						Location:        path,
						Exists:          true,
						RiskLevel:       core.AssessRisk(core.PlaintextJSON, path),
						ValuePreview:    core.MaskValue(apiKey, showSecrets),
						RawValue:        rawValue,
						FilePermissions: perms,
						FileOwner:       owner,
						FileModified:    core.GetFileMtime(path),
						Remediation:     "Use environment variables instead of inline API keys in config",
						RemediationHint: remediation.HintMigrateToEnv([]string{}, path),
						Notes:           notes,
					})
				}
			}
		}
	}

	// Check tabAutocompleteModel
	if tabRaw, ok := parsed["tabAutocompleteModel"]; ok {
		if tabModel, ok := tabRaw.(map[string]interface{}); ok {
			if apiKeyRaw, ok := tabModel["apiKey"]; ok {
				if apiKey, ok := apiKeyRaw.(string); ok && apiKey != "" && !strings.Contains(apiKey, "${") {
					rawValue := ""
					if showSecrets {
						rawValue = apiKey
					}
					notes := []string{"PLAINTEXT API key in config!"}
					if mtime := core.GetFileMtimeTime(path); !mtime.IsZero() {
						notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
					}
					result.Findings = append(result.Findings, core.CredentialFinding{
						ToolName:        s.Name(),
						CredentialType:  "tabAutocomplete api_key",
						StorageType:     core.PlaintextJSON,
						Location:        path,
						Exists:          true,
						RiskLevel:       core.AssessRisk(core.PlaintextJSON, path),
						ValuePreview:    core.MaskValue(apiKey, showSecrets),
						RawValue:        rawValue,
						FilePermissions: perms,
						FileOwner:       owner,
						FileModified:    core.GetFileMtime(path),
						Remediation:     "Use environment variables instead of inline API keys in config",
						RemediationHint: remediation.HintMigrateToEnv([]string{}, path),
						Notes:           notes,
					})
				}
			}
		}
	}
}
