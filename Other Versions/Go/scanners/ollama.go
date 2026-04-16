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

// ollamaEnvVars maps environment variable names to descriptions.
var ollamaEnvVars = map[string]string{
	"OLLAMA_HOST":         "Ollama server bind address (default: 127.0.0.1:11434)",
	"OLLAMA_ORIGINS":      "Ollama CORS allowed origins",
	"OLLAMA_MODELS":       "Ollama model storage directory",
	"OLLAMA_DEBUG":        "Ollama debug mode flag",
	"OLLAMA_API_KEY":      "Ollama API key (if using proxy/auth layer)",
	"OLLAMA_NUM_PARALLEL": "Ollama concurrent request limit",
}

type ollamaScanner struct{}

func init() {
	Register(&ollamaScanner{})
}

func (s *ollamaScanner) Name() string      { return "Ollama" }
func (s *ollamaScanner) Slug() string       { return "ollama" }
func (s *ollamaScanner) IsApplicable() bool { return true }

func (s *ollamaScanner) Scan(showSecrets bool) core.ScanResult {
	result := core.ScanResult{ScannerName: s.Name(), Platform: core.DetectPlatform().String()}
	plat := core.DetectPlatform()

	// Check environment variables
	s.scanEnvVars(&result, showSecrets)

	// Check for dangerous network binding
	s.checkNetworkExposure(&result)

	// Check systemd service file (Linux/WSL)
	if plat == core.PlatformLinux || plat == core.PlatformWSL {
		s.scanSystemdService(&result, showSecrets)
	}

	// Check config directories
	for _, path := range s.getConfigPaths(plat) {
		s.scanConfigDir(path, &result, showSecrets)
	}

	return result
}

func (s *ollamaScanner) getConfigPaths(plat core.Platform) []string {
	home := core.GetHome()
	paths := []string{filepath.Join(home, ".ollama")}

	if plat == core.PlatformLinux || plat == core.PlatformWSL {
		paths = append(paths, "/usr/share/ollama/.ollama")
	}

	if plat == core.PlatformWSL {
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			paths = append(paths, filepath.Join(winHome, ".ollama"))
		}
	}

	return paths
}

func (s *ollamaScanner) scanEnvVars(result *core.ScanResult, showSecrets bool) {
	for varName, description := range ollamaEnvVars {
		value := os.Getenv(varName)
		if value == "" {
			continue
		}

		// Dangerous OLLAMA_HOST binding
		if varName == "OLLAMA_HOST" && strings.Contains(value, "0.0.0.0") {
			result.Findings = append(result.Findings, core.CredentialFinding{
				ToolName:       s.Name(),
				CredentialType: "network_binding",
				StorageType:    core.EnvironmentVar,
				Location:       fmt.Sprintf("$%s", varName),
				Exists:         true,
				RiskLevel:      core.RiskHigh,
				ValuePreview:   value,
				Remediation:    "Bind to 127.0.0.1 instead of 0.0.0.0",
				RemediationHint: remediation.HintNetworkBind("ollama", "", 11434),
				Notes: []string{
					"Ollama API bound to all interfaces (0.0.0.0)",
					"No built-in authentication — any network device can access the API",
				},
			})
			continue
		}

		// Wildcard CORS
		if varName == "OLLAMA_ORIGINS" && value == "*" {
			result.Findings = append(result.Findings, core.CredentialFinding{
				ToolName:       s.Name(),
				CredentialType: "cors_config",
				StorageType:    core.EnvironmentVar,
				Location:       fmt.Sprintf("$%s", varName),
				Exists:         true,
				RiskLevel:      core.RiskMedium,
				ValuePreview:   value,
				Remediation:    "Restrict CORS origins",
				RemediationHint: remediation.HintChangeConfigValue("OLLAMA_ORIGINS", "https://your-allowed-origin.example", fmt.Sprintf("$%s", varName)),
				Notes:          []string{"Wildcard CORS — any website can make requests to Ollama API"},
			})
			continue
		}

		// API key
		if varName == "OLLAMA_API_KEY" {
			rawValue := ""
			if showSecrets {
				rawValue = value
			}
			result.Findings = append(result.Findings, core.CredentialFinding{
				ToolName:       s.Name(),
				CredentialType: "api_key",
				StorageType:    core.EnvironmentVar,
				Location:       fmt.Sprintf("$%s", varName),
				Exists:         true,
				RiskLevel:      core.RiskMedium,
				ValuePreview:   core.MaskValue(value, showSecrets),
				RawValue:       rawValue,
				Remediation:    "Use environment variables securely",
				RemediationHint: remediation.HintManual("Use environment variables securely"),
				Notes:          []string{"Ollama API key (likely for auth proxy)"},
			})
			continue
		}

		// Non-secret config flags
		result.Findings = append(result.Findings, core.CredentialFinding{
			ToolName:       s.Name(),
			CredentialType: description,
			StorageType:    core.EnvironmentVar,
			Location:       fmt.Sprintf("$%s", varName),
			Exists:         true,
			RiskLevel:      core.RiskInfo,
			ValuePreview:   value,
			Remediation:    "Use environment variables securely",
			Notes:          []string{"Configuration flag"},
		})
	}
}

func (s *ollamaScanner) checkNetworkExposure(result *core.ScanResult) {
	cmd := exec.Command("ss", "-tlnp")
	output, err := cmd.Output()
	if err != nil {
		return
	}

	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, ":11434") && strings.Contains(line, "0.0.0.0") {
			result.Findings = append(result.Findings, core.CredentialFinding{
				ToolName:       s.Name(),
				CredentialType: "network_exposure",
				StorageType:    core.StorageUnknown,
				Location:       "listening on 0.0.0.0:11434",
				Exists:         true,
				RiskLevel:      core.RiskCritical,
				Remediation:    "Bind to 127.0.0.1 instead of 0.0.0.0",
				Notes: []string{
					"Ollama API is currently listening on all interfaces",
					"No built-in authentication — any device on the network can run inference",
					"Recommendation: bind to 127.0.0.1 or use a reverse proxy with auth",
				},
			})
			break
		}
	}
}

func (s *ollamaScanner) scanSystemdService(result *core.ScanResult, showSecrets bool) {
	servicePaths := []string{
		"/etc/systemd/system/ollama.service",
		"/usr/lib/systemd/system/ollama.service",
	}

	for _, path := range servicePaths {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		perms := core.GetFilePermissions(path)
		owner := core.GetFileOwner(path)

		for _, line := range strings.Split(string(raw), "\n") {
			stripped := strings.TrimSpace(line)
			if !strings.HasPrefix(stripped, "Environment=") && !strings.HasPrefix(stripped, "Environment =") {
				continue
			}

			idx := strings.Index(stripped, "=")
			envVal := strings.TrimSpace(stripped[idx+1:])
			envVal = strings.Trim(envVal, "\"")

			// Check for OLLAMA_HOST=0.0.0.0
			if strings.Contains(envVal, "OLLAMA_HOST") && strings.Contains(envVal, "0.0.0.0") {
				notes := []string{
					"Ollama systemd service configured to bind to 0.0.0.0",
					"API exposed to network without authentication",
				}
				if mtime := core.GetFileMtimeTime(path); !mtime.IsZero() {
					notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
				}
				result.Findings = append(result.Findings, core.CredentialFinding{
					ToolName:        s.Name(),
					CredentialType:  "systemd_network_binding",
					StorageType:     core.PlaintextINI,
					Location:        path,
					Exists:          true,
					RiskLevel:       core.RiskHigh,
					ValuePreview:    envVal,
					FilePermissions: perms,
					FileOwner:       owner,
					FileModified:    core.GetFileMtime(path),
					Remediation:     "Bind to 127.0.0.1 instead of 0.0.0.0",
					RemediationHint: remediation.HintNetworkBind("ollama", path, 11434),
					Notes:           notes,
				})
			}

			// Check for secret-looking values
			envUpper := strings.ToUpper(envVal)
			for _, kw := range []string{"KEY", "TOKEN", "SECRET", "PASSWORD"} {
				if strings.Contains(envUpper, kw) {
					rawValue := ""
					if showSecrets {
						rawValue = envVal
					}
					notes := []string{"Secret in Ollama systemd service file"}
					if mtime := core.GetFileMtimeTime(path); !mtime.IsZero() {
						notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
					}
					result.Findings = append(result.Findings, core.CredentialFinding{
						ToolName:        s.Name(),
						CredentialType:  "systemd_env_secret",
						StorageType:     core.PlaintextINI,
						Location:        path,
						Exists:          true,
						RiskLevel:       core.AssessRisk(core.PlaintextINI, path),
						ValuePreview:    core.MaskValue(envVal, showSecrets),
						RawValue:        rawValue,
						FilePermissions: perms,
						FileOwner:       owner,
						FileModified:    core.GetFileMtime(path),
						Remediation:     "Use environment variables securely",
						RemediationHint: remediation.HintManual("Use environment variables securely"),
						Notes:           notes,
					})
					break
				}
			}
		}
	}
}

func (s *ollamaScanner) scanConfigDir(basePath string, result *core.ScanResult, showSecrets bool) {
	if _, err := os.Stat(basePath); err != nil {
		return
	}

	matches, _ := filepath.Glob(filepath.Join(basePath, "*.json"))
	for _, jsonFile := range matches {
		data, err := os.ReadFile(jsonFile)
		if err != nil {
			continue
		}

		perms := core.GetFilePermissions(jsonFile)
		owner := core.GetFileOwner(jsonFile)

		var obj map[string]interface{}
		if err := json.Unmarshal(data, &obj); err != nil {
			continue
		}

		for _, key := range []string{"api_key", "apiKey", "token", "auth_token", "password"} {
			val, ok := obj[key]
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
			if mtime := core.GetFileMtimeTime(jsonFile); !mtime.IsZero() {
				notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
			}
			result.Findings = append(result.Findings, core.CredentialFinding{
				ToolName:        s.Name(),
				CredentialType:  key,
				StorageType:     core.PlaintextJSON,
				Location:        jsonFile,
				Exists:          true,
				RiskLevel:       core.AssessRisk(core.PlaintextJSON, jsonFile),
				ValuePreview:    core.MaskValue(value, showSecrets),
				RawValue:        rawValue,
				FilePermissions: perms,
				FileOwner:       owner,
				FileModified:    core.GetFileMtime(jsonFile),
				Remediation:     "Use environment variables securely",
				RemediationHint: remediation.HintManual("Use environment variables securely"),
				Notes:           notes,
			})
		}
	}
}
