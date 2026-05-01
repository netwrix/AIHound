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

type githubCopilotScanner struct{}

func init() {
	Register(&githubCopilotScanner{})
}

func (s *githubCopilotScanner) Name() string      { return "GitHub Copilot" }
func (s *githubCopilotScanner) Slug() string       { return "github-copilot" }
func (s *githubCopilotScanner) IsApplicable() bool { return true }

func (s *githubCopilotScanner) Scan(showSecrets bool) core.ScanResult {
	result := core.ScanResult{ScannerName: s.Name(), Platform: core.DetectPlatform().String()}
	plat := core.DetectPlatform()

	for _, p := range s.getCopilotConfigPaths(plat) {
		s.scanCopilotConfig(p, &result, showSecrets)
	}

	for _, p := range s.getVSCodeCopilotPaths(plat) {
		s.scanCopilotConfig(p, &result, showSecrets)
	}

	return result
}

func (s *githubCopilotScanner) getCopilotConfigPaths(plat core.Platform) []string {
	var paths []string
	home := core.GetHome()

	// ~/.copilot/config.json
	paths = append(paths, filepath.Join(home, ".copilot", "config.json"))

	// GitHub CLI auth config
	switch plat {
	case core.PlatformLinux:
		paths = append(paths, filepath.Join(core.GetXDGConfig(), "gh", "hosts.yml"))
	case core.PlatformMacOS:
		paths = append(paths, filepath.Join(home, "Library", "Application Support", "gh", "hosts.yml"))
	case core.PlatformWindows:
		if appdata := core.GetAppData(); appdata != "" {
			paths = append(paths, filepath.Join(appdata, "GitHub CLI", "hosts.yml"))
		}
	case core.PlatformWSL:
		paths = append(paths, filepath.Join(core.GetXDGConfig(), "gh", "hosts.yml"))
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			paths = append(paths, filepath.Join(winHome, ".copilot", "config.json"))
		}
		if appdata := core.GetAppData(); appdata != "" {
			paths = append(paths, filepath.Join(appdata, "GitHub CLI", "hosts.yml"))
		}
	}

	return paths
}

func (s *githubCopilotScanner) getVSCodeCopilotPaths(plat core.Platform) []string {
	var paths []string

	addPaths := func(base string) {
		paths = append(paths,
			filepath.Join(base, "github.copilot", "hosts.json"),
			filepath.Join(base, "github.copilot-chat", "hosts.json"),
		)
	}

	switch plat {
	case core.PlatformLinux:
		addPaths(filepath.Join(core.GetXDGConfig(), "Code", "User", "globalStorage"))
	case core.PlatformMacOS:
		addPaths(filepath.Join(core.GetHome(), "Library", "Application Support", "Code", "User", "globalStorage"))
	case core.PlatformWindows:
		if appdata := core.GetAppData(); appdata != "" {
			addPaths(filepath.Join(appdata, "Code", "User", "globalStorage"))
		}
	case core.PlatformWSL:
		addPaths(filepath.Join(core.GetXDGConfig(), "Code", "User", "globalStorage"))
		if appdata := core.GetAppData(); appdata != "" {
			addPaths(filepath.Join(appdata, "Code", "User", "globalStorage"))
		}
	}

	return paths
}

func (s *githubCopilotScanner) scanCopilotConfig(path string, result *core.ScanResult, showSecrets bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	perms := core.GetFilePermissions(path)
	owner := core.GetFileOwner(path)
	content := string(data)

	// Try JSON first
	var jsonData map[string]interface{}
	if err := json.Unmarshal(data, &jsonData); err == nil {
		s.extractTokensFromJSON(jsonData, path, perms, owner, result, showSecrets)
		return
	}

	// Fall back to simple YAML parsing for hosts.yml
	s.extractTokensFromYAML(content, path, perms, owner, result, showSecrets)
}

func (s *githubCopilotScanner) extractTokensFromJSON(
	data map[string]interface{}, path, perms, owner string,
	result *core.ScanResult, showSecrets bool,
) {
	for key, val := range data {
		switch v := val.(type) {
		case string:
			if len(v) > 10 {
				keyLower := strings.ToLower(key)
				if strings.Contains(keyLower, "token") || strings.Contains(keyLower, "oauth") || strings.Contains(keyLower, "key") {
					storage := core.PlaintextJSON
					rawValue := ""
					if showSecrets {
						rawValue = v
					}
					var notes []string
					if mtime := core.GetFileMtimeTime(path); !mtime.IsZero() {
						notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
					}
					result.Findings = append(result.Findings, core.CredentialFinding{
						ToolName:        s.Name(),
						CredentialType:  fmt.Sprintf("copilot:%s", key),
						StorageType:     storage,
						Location:        path,
						Exists:          true,
						RiskLevel:       core.AssessRisk(storage, path),
						ValuePreview:    core.MaskValue(v, showSecrets),
						RawValue:        rawValue,
						FilePermissions: perms,
						FileOwner:       owner,
						FileModified:    core.GetFileMtime(path),
						Remediation:     chmodRemediation(path),
						RemediationHint: chmodRemediationHint(path),
						Notes:           notes,
					})
				}
			}
		case map[string]interface{}:
			s.extractTokensFromJSON(v, path, perms, owner, result, showSecrets)
		}
	}
}

func (s *githubCopilotScanner) extractTokensFromYAML(
	content, path, perms, owner string,
	result *core.ScanResult, showSecrets bool,
) {
	for _, line := range strings.Split(content, "\n") {
		stripped := strings.TrimSpace(line)
		if !strings.Contains(stripped, ":") {
			continue
		}

		parts := strings.SplitN(stripped, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		keyLower := strings.ToLower(key)
		if (keyLower == "oauth_token" || keyLower == "token") && value != "" {
			storage := core.PlaintextYAML
			rawValue := ""
			if showSecrets {
				rawValue = value
			}
			notes := []string{"GitHub CLI auth config"}
			if mtime := core.GetFileMtimeTime(path); !mtime.IsZero() {
				notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
			}
			result.Findings = append(result.Findings, core.CredentialFinding{
				ToolName:        s.Name(),
				CredentialType:  fmt.Sprintf("gh_cli:%s", key),
				StorageType:     storage,
				Location:        path,
				Exists:          true,
				RiskLevel:       core.AssessRisk(storage, path),
				ValuePreview:    core.MaskValue(value, showSecrets),
				RawValue:        rawValue,
				FilePermissions: perms,
				FileOwner:       owner,
				FileModified:    core.GetFileMtime(path),
				Remediation:     "Use GitHub CLI (gh auth) for secure token storage",
				RemediationHint: remediation.HintUseCredentialHelper("gh", []string{"gh auth login"}),
				Notes:           notes,
			})
		}
	}
}
