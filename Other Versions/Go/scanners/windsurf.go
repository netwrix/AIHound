package scanners

import (
	"encoding/json"
	"os"
	"path/filepath"

	"aihound/core"
	"aihound/remediation"
)

type windsurfScanner struct{}

func init() {
	Register(&windsurfScanner{})
}

func (s *windsurfScanner) Name() string      { return "Windsurf" }
func (s *windsurfScanner) Slug() string       { return "windsurf" }
func (s *windsurfScanner) IsApplicable() bool { return true }

func (s *windsurfScanner) Scan(showSecrets bool) core.ScanResult {
	result := core.ScanResult{ScannerName: s.Name(), Platform: core.DetectPlatform().String()}
	plat := core.DetectPlatform()

	for _, p := range s.getConfigPaths(plat) {
		s.scanConfigDir(p, &result, showSecrets)
	}

	for _, p := range s.getMCPPaths(plat) {
		findings := core.ParseMCPFile(p, s.Name(), showSecrets)
		result.Findings = append(result.Findings, findings...)
	}

	return result
}

func (s *windsurfScanner) getConfigPaths(plat core.Platform) []string {
	var paths []string
	home := core.GetHome()

	paths = append(paths, filepath.Join(home, ".codeium", "windsurf"))

	if plat == core.PlatformWSL {
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			paths = append(paths, filepath.Join(winHome, ".codeium", "windsurf"))
		}
	}

	return paths
}

func (s *windsurfScanner) getMCPPaths(plat core.Platform) []string {
	var paths []string
	home := core.GetHome()

	paths = append(paths, filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"))

	if plat == core.PlatformWSL {
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			paths = append(paths, filepath.Join(winHome, ".codeium", "windsurf", "mcp_config.json"))
		}
	}

	return paths
}

func (s *windsurfScanner) scanConfigDir(basePath string, result *core.ScanResult, showSecrets bool) {
	info, err := os.Stat(basePath)
	if err != nil || !info.IsDir() {
		return
	}

	authFiles := []string{"config.json", "auth.json", "credentials.json"}

	for _, fname := range authFiles {
		path := filepath.Join(basePath, fname)
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

func (s *windsurfScanner) extractTokens(
	data map[string]interface{}, path, perms, owner string,
	result *core.ScanResult, showSecrets bool,
) {
	tokenKeys := []string{"api_key", "apiKey", "token", "auth_token", "access_token", "refresh_token"}

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
			Remediation:     "Restrict file permissions: chmod 600 " + path,
			RemediationHint: remediation.HintChmod("600", path),
			Notes:           notes,
		})
	}
}
