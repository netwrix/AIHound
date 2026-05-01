package scanners

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"aihound/core"
	"aihound/remediation"
)

// lmStudioSecretKeys are JSON keys that indicate credentials.
var lmStudioSecretKeys = []string{
	"api_key", "apiKey", "token", "auth_token", "access_token",
	"hf_token", "huggingface_token", "huggingFaceToken",
	"password", "secret",
}

type lmStudioScanner struct{}

func init() {
	Register(&lmStudioScanner{})
}

func (s *lmStudioScanner) Name() string      { return "LM Studio" }
func (s *lmStudioScanner) Slug() string       { return "lm-studio" }
func (s *lmStudioScanner) IsApplicable() bool { return true }

func (s *lmStudioScanner) Scan(showSecrets bool) core.ScanResult {
	result := core.ScanResult{ScannerName: s.Name(), Platform: core.DetectPlatform().String()}
	plat := core.DetectPlatform()

	for _, path := range s.getConfigPaths(plat) {
		s.scanConfigDir(path, &result, showSecrets)
	}

	s.checkNetworkExposure(&result)

	return result
}

func (s *lmStudioScanner) getConfigPaths(plat core.Platform) []string {
	var paths []string
	home := core.GetHome()

	switch plat {
	case core.PlatformMacOS:
		paths = append(paths, filepath.Join(home, "Library", "Application Support", "LM Studio"))

	case core.PlatformWindows:
		if appdata := core.GetAppData(); appdata != "" {
			paths = append(paths, filepath.Join(appdata, "LM Studio"))
		}
		paths = append(paths, filepath.Join(home, "AppData", "Local", "LM Studio"))

	case core.PlatformLinux, core.PlatformWSL:
		paths = append(paths, filepath.Join(core.GetXDGConfig(), "LM Studio"))
		// Flatpak path
		paths = append(paths, filepath.Join(home, ".var", "app", "com.lmstudio.lmstudio", "config", "LM Studio"))
	}

	if plat == core.PlatformWSL {
		if appdata := core.GetAppData(); appdata != "" {
			paths = append(paths, filepath.Join(appdata, "LM Studio"))
		}
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			paths = append(paths, filepath.Join(winHome, "AppData", "Local", "LM Studio"))
		}
	}

	return paths
}

func (s *lmStudioScanner) scanConfigDir(basePath string, result *core.ScanResult, showSecrets bool) {
	if _, err := os.Stat(basePath); err != nil {
		return
	}

	// Scan JSON files in config directory
	jsonFiles, _ := filepath.Glob(filepath.Join(basePath, "*.json"))

	// Also check common subdirectories
	for _, subdir := range []string{"config", "settings", "auth"} {
		sub := filepath.Join(basePath, subdir)
		if _, err := os.Stat(sub); err == nil {
			matches, _ := filepath.Glob(filepath.Join(sub, "*.json"))
			jsonFiles = append(jsonFiles, matches...)
		}
	}

	for _, jsonFile := range jsonFiles {
		s.scanJSONFile(jsonFile, result, showSecrets)
	}

	// Check for .env files
	envFiles, _ := filepath.Glob(filepath.Join(basePath, "*.env"))
	for _, envFile := range envFiles {
		s.scanEnvFile(envFile, result, showSecrets)
	}
	dotEnv := filepath.Join(basePath, ".env")
	if _, err := os.Stat(dotEnv); err == nil {
		s.scanEnvFile(dotEnv, result, showSecrets)
	}
}

func (s *lmStudioScanner) scanJSONFile(path string, result *core.ScanResult, showSecrets bool) {
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

	s.extractSecrets(obj, path, perms, owner, result, showSecrets)
}

func (s *lmStudioScanner) extractSecrets(
	data map[string]interface{}, path, perms, owner string,
	result *core.ScanResult, showSecrets bool,
) {
	storage := core.PlaintextJSON

	// Check direct secret keys
	for _, key := range lmStudioSecretKeys {
		val, ok := data[key]
		if !ok {
			continue
		}
		value, ok := val.(string)
		if !ok || len(value) <= 8 {
			continue
		}

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
			Remediation:     chmodRemediation(path),
			RemediationHint: chmodRemediationHint(path),
			Notes:           notes,
		})
	}

	// Check nested structures for HF auth etc.
	for _, nestedKey := range []string{"huggingFace", "huggingface", "hf", "auth", "credentials"} {
		if nested, ok := data[nestedKey].(map[string]interface{}); ok {
			s.extractSecrets(nested, path, perms, owner, result, showSecrets)
		}
	}

	// Check for server config exposing non-localhost binding
	for _, serverKey := range []string{"server", "localServer"} {
		server, ok := data[serverKey].(map[string]interface{})
		if !ok {
			continue
		}
		host, _ := server["host"].(string)
		portStr := ""
		portInt := 0
		switch p := server["port"].(type) {
		case string:
			portStr = p
		case float64:
			portInt = int(p)
			portStr = fmt.Sprintf("%d", portInt)
		}
		if strings.Contains(host, "0.0.0.0") {
			notes := []string{
				"LM Studio server configured to bind to all interfaces",
				"No built-in authentication — network devices can access the API",
			}
			if mtime := core.GetFileMtimeTime(path); !mtime.IsZero() {
				notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
			}
			result.Findings = append(result.Findings, core.CredentialFinding{
				ToolName:        s.Name(),
				CredentialType:  "server_network_binding",
				StorageType:     core.PlaintextJSON,
				Location:        path,
				Exists:          true,
				RiskLevel:       core.RiskHigh,
				ValuePreview:    fmt.Sprintf("%s:%s", host, portStr),
				FilePermissions: perms,
				FileOwner:       owner,
				FileModified:    core.GetFileMtime(path),
				Remediation:     "Bind to 127.0.0.1 instead of 0.0.0.0",
				RemediationHint: remediation.HintNetworkBind("lm-studio", path, portInt),
				Notes:           notes,
			})
		}
	}
}

func (s *lmStudioScanner) scanEnvFile(path string, result *core.ScanResult, showSecrets bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}

	perms := core.GetFilePermissions(path)
	owner := core.GetFileOwner(path)
	storage := core.PlaintextENV

	secretPatterns := []string{"KEY", "TOKEN", "SECRET", "PASSWORD", "AUTH"}
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
				notes := []string{"From .env file in LM Studio config"}
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
					Remediation:     chmodRemediation(path),
					RemediationHint: chmodRemediationHint(path),
					Notes:           notes,
				})
			}
		}
	}
}

func (s *lmStudioScanner) checkNetworkExposure(result *core.ScanResult) {
	cmd := exec.Command("ss", "-tlnp")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, ":1234") && strings.Contains(line, "0.0.0.0") {
			result.Findings = append(result.Findings, core.CredentialFinding{
				ToolName:       s.Name(),
				CredentialType: "network_exposure",
				StorageType:    core.StorageUnknown,
				Location:       "listening on 0.0.0.0:1234",
				Exists:         true,
				RiskLevel:      core.RiskCritical,
				Remediation:    "Bind to 127.0.0.1 instead of 0.0.0.0",
				RemediationHint: remediation.HintNetworkBind("lm-studio", "", 1234),
				Notes: []string{
					"LM Studio API server listening on all interfaces",
					"No built-in authentication — network devices can access the API",
					"Recommendation: bind to 127.0.0.1 or use a reverse proxy with auth",
				},
			})
			break
		}
	}
}
