package scanners

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aihound/core"
	"aihound/remediation"
)

var aiderSecretKeyTokens = []string{"key", "token", "secret", "password", "passwd", "auth", "credential"}

type aiderScanner struct{}

func init() {
	Register(&aiderScanner{})
}

func (s *aiderScanner) Name() string        { return "Aider" }
func (s *aiderScanner) Slug() string         { return "aider" }
func (s *aiderScanner) IsApplicable() bool   { return true }

func (s *aiderScanner) Scan(showSecrets bool) core.ScanResult {
	result := core.ScanResult{ScannerName: s.Name(), Platform: core.DetectPlatform().String()}
	plat := core.DetectPlatform()

	for _, p := range s.getConfigPaths(plat) {
		s.scanConfig(p, &result, showSecrets)
	}

	return result
}

func (s *aiderScanner) getConfigPaths(plat core.Platform) []string {
	var paths []string
	home := core.GetHome()
	paths = append(paths, filepath.Join(home, ".aider.conf.yml"))
	paths = append(paths, filepath.Join(home, ".aider.conf.yaml"))

	if plat == core.PlatformWSL {
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			paths = append(paths, filepath.Join(winHome, ".aider.conf.yml"))
			paths = append(paths, filepath.Join(winHome, ".aider.conf.yaml"))
		}
	}
	return paths
}

func (s *aiderScanner) scanConfig(path string, result *core.ScanResult, showSecrets bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	perms := core.GetFilePermissions(path)
	owner := core.GetFileOwner(path)
	storage := core.PlaintextYAML

	for _, rawLine := range strings.Split(string(data), "\n") {
		stripped := strings.TrimSpace(rawLine)
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			continue
		}
		if !strings.Contains(stripped, ":") {
			continue
		}
		idx := strings.Index(stripped, ":")
		key := strings.TrimSpace(stripped[:idx])
		value := strings.TrimSpace(stripped[idx+1:])
		if value == "" {
			continue
		}

		// Strip inline comments (if value isn't quoted)
		if strings.Contains(value, "#") {
			if !(strings.HasPrefix(value, "\"") || strings.HasPrefix(value, "'")) {
				value = strings.TrimSpace(strings.SplitN(value, "#", 2)[0])
			}
		}

		// Strip surrounding quotes
		if len(value) >= 2 {
			first := value[0]
			last := value[len(value)-1]
			if first == last && (first == '"' || first == '\'') {
				value = value[1 : len(value)-1]
			}
		}
		if value == "" {
			continue
		}

		keyLower := strings.ToLower(key)
		matched := false
		for _, tok := range aiderSecretKeyTokens {
			if strings.Contains(keyLower, tok) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		valueLower := strings.ToLower(value)
		if valueLower == "true" || valueLower == "false" || valueLower == "yes" || valueLower == "no" || valueLower == "null" || valueLower == "~" {
			continue
		}

		notes := []string{fmt.Sprintf("Aider config key: %s", key)}
		if mtime := core.GetFileMtimeTime(path); !mtime.IsZero() {
			notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
		}

		rawValue := ""
		if showSecrets {
			rawValue = value
		}

		result.Findings = append(result.Findings, core.CredentialFinding{
			ToolName:        s.Name(),
			CredentialType:  fmt.Sprintf("aider:%s", key),
			StorageType:     storage,
			Location:        path,
			Exists:          true,
			RiskLevel:       core.AssessRisk(storage, path),
			ValuePreview:    core.MaskValue(value, showSecrets),
			RawValue:        rawValue,
			FilePermissions: perms,
			FileOwner:       owner,
			FileModified:    core.GetFileMtime(path),
			Remediation:     "Use environment variables (OPENAI_API_KEY, ANTHROPIC_API_KEY) instead of config file",
			RemediationHint: remediation.HintMigrateToEnv([]string{"OPENAI_API_KEY", "ANTHROPIC_API_KEY"}, path),
			Notes:           notes,
		})
	}
}
