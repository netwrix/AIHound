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

type geminiScanner struct{}

func init() {
	Register(&geminiScanner{})
}

func (s *geminiScanner) Name() string      { return "Gemini CLI / GCloud" }
func (s *geminiScanner) Slug() string       { return "gemini" }
func (s *geminiScanner) IsApplicable() bool { return true }

func (s *geminiScanner) Scan(showSecrets bool) core.ScanResult {
	result := core.ScanResult{ScannerName: s.Name(), Platform: core.DetectPlatform().String()}
	plat := core.DetectPlatform()

	// Check .env files
	for _, path := range s.getEnvFilePaths(plat) {
		s.scanEnvFile(path, &result, showSecrets)
	}

	// Check Application Default Credentials
	for _, path := range s.getADCPaths(plat) {
		s.scanADC(path, &result, showSecrets)
	}

	return result
}

func (s *geminiScanner) getEnvFilePaths(plat core.Platform) []string {
	home := core.GetHome()
	paths := []string{
		filepath.Join(home, ".gemini", ".env"),
		filepath.Join(home, ".env"),
	}

	if plat == core.PlatformWSL {
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			paths = append(paths,
				filepath.Join(winHome, ".gemini", ".env"),
				filepath.Join(winHome, ".env"),
			)
		}
	}

	return paths
}

func (s *geminiScanner) getADCPaths(plat core.Platform) []string {
	var paths []string

	switch plat {
	case core.PlatformLinux, core.PlatformWSL:
		paths = append(paths,
			filepath.Join(core.GetXDGConfig(), "gcloud", "application_default_credentials.json"),
		)

	case core.PlatformMacOS:
		home := core.GetHome()
		paths = append(paths,
			filepath.Join(home, "Library", "Application Support", "gcloud", "application_default_credentials.json"),
			filepath.Join(home, ".config", "gcloud", "application_default_credentials.json"),
		)

	case core.PlatformWindows:
		if appdata := core.GetAppData(); appdata != "" {
			paths = append(paths,
				filepath.Join(appdata, "gcloud", "application_default_credentials.json"),
			)
		}
	}

	// WSL: also check Windows AppData
	if plat == core.PlatformWSL {
		if appdata := core.GetAppData(); appdata != "" {
			paths = append(paths,
				filepath.Join(appdata, "gcloud", "application_default_credentials.json"),
			)
		}
	}

	return paths
}

func (s *geminiScanner) scanEnvFile(path string, result *core.ScanResult, showSecrets bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}

	perms := core.GetFilePermissions(path)
	owner := core.GetFileOwner(path)
	storage := core.PlaintextENV

	geminiKeys := map[string]bool{
		"GEMINI_API_KEY":                 true,
		"GOOGLE_API_KEY":                 true,
		"GOOGLE_APPLICATION_CREDENTIALS": true,
		"OPENAI_API_KEY":                 true,
		"ANTHROPIC_API_KEY":              true,
	}

	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if idx := strings.Index(line, "="); idx >= 0 {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			value = strings.Trim(value, "'\"")

			if value != "" && geminiKeys[key] {
				rawValue := ""
				if showSecrets {
					rawValue = value
				}
				notes := []string{"From .env file"}
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
					Remediation:     "Use environment variables instead of .env files",
					RemediationHint: remediation.HintMigrateToEnv([]string{}, path),
					Notes:           notes,
				})
			}
		}
	}
}

func (s *geminiScanner) scanADC(path string, result *core.ScanResult, showSecrets bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	perms := core.GetFilePermissions(path)
	owner := core.GetFileOwner(path)
	storage := core.PlaintextJSON

	var obj map[string]interface{}
	if err := json.Unmarshal(data, &obj); err != nil {
		return
	}

	// ADC files contain client_secret, refresh_token, etc.
	tokenFields := []struct {
		fieldName string
		credType  string
	}{
		{"client_secret", "gcloud_client_secret"},
		{"refresh_token", "gcloud_refresh_token"},
		{"private_key", "service_account_key"},
	}

	for _, tf := range tokenFields {
		val, ok := obj[tf.fieldName].(string)
		if !ok || val == "" {
			continue
		}

		credKind, _ := obj["type"].(string)
		if credKind == "" {
			credKind = "unknown"
		}

		rawValue := ""
		if showSecrets {
			rawValue = val
		}
		notes := []string{fmt.Sprintf("Credential type: %s", credKind)}
		if mtime := core.GetFileMtimeTime(path); !mtime.IsZero() {
			notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
		}
		result.Findings = append(result.Findings, core.CredentialFinding{
			ToolName:        s.Name(),
			CredentialType:  tf.credType,
			StorageType:     storage,
			Location:        path,
			Exists:          true,
			RiskLevel:       core.AssessRisk(storage, path),
			ValuePreview:    core.MaskValue(val, showSecrets),
			RawValue:        rawValue,
			FilePermissions: perms,
			FileOwner:       owner,
			FileModified:    core.GetFileMtime(path),
			Remediation:     "Rotate Application Default Credentials regularly",
			RemediationHint: remediation.HintRotateCredential("gcloud-adc", "Rotate Application Default Credentials regularly"),
			Notes:           notes,
		})
	}
}
