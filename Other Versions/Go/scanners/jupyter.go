package scanners

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"aihound/core"
	"aihound/remediation"
)

var jupyterPyConfigRe = regexp.MustCompile(`(?i)c\.(?:NotebookApp|ServerApp|Notebook)\.(token|password)\s*=\s*(['"])([^'"]*)['"]`)

var jupyterSecretKeywords = []string{
	"token", "key", "secret", "password", "passwd", "auth",
	"credential", "cred", "api_key", "apikey", "access_key",
}

const jupyterTokenRemediation = "Set a strong token or password hash; avoid binding to 0.0.0.0 or use an authentication proxy"
const jupyterKernelRemediation = "Move API keys out of kernel.json env; use environment variables or secret managers"

type jupyterScanner struct{}

func init() {
	Register(&jupyterScanner{})
}

func (s *jupyterScanner) Name() string        { return "Jupyter" }
func (s *jupyterScanner) Slug() string         { return "jupyter" }
func (s *jupyterScanner) IsApplicable() bool   { return true }

func (s *jupyterScanner) Scan(showSecrets bool) core.ScanResult {
	result := core.ScanResult{ScannerName: s.Name(), Platform: core.DetectPlatform().String()}
	plat := core.DetectPlatform()

	for _, p := range s.getConfigPaths(plat) {
		ext := strings.ToLower(filepath.Ext(p))
		if ext == ".py" {
			s.scanPyConfig(p, &result, showSecrets)
		} else if ext == ".json" {
			s.scanJSONConfig(p, &result, showSecrets)
		}
	}

	for _, p := range s.getKernelPaths(plat) {
		s.scanKernelJSON(p, &result, showSecrets)
	}

	return result
}

func (s *jupyterScanner) getConfigPaths(plat core.Platform) []string {
	var paths []string
	home := core.GetHome()
	configNames := []string{
		"jupyter_notebook_config.py",
		"jupyter_notebook_config.json",
		"jupyter_server_config.py",
		"jupyter_server_config.json",
	}
	for _, name := range configNames {
		paths = append(paths, filepath.Join(home, ".jupyter", name))
	}

	if plat == core.PlatformWSL {
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			for _, name := range configNames {
				paths = append(paths, filepath.Join(winHome, ".jupyter", name))
			}
		}
	}

	if plat == core.PlatformWindows || plat == core.PlatformWSL {
		if appdata := core.GetAppData(); appdata != "" {
			for _, name := range configNames {
				paths = append(paths, filepath.Join(appdata, "jupyter", name))
			}
		}
	}

	return paths
}

func (s *jupyterScanner) getKernelPaths(plat core.Platform) []string {
	var kernelFiles []string
	home := core.GetHome()

	baseDirs := []string{filepath.Join(home, ".local", "share", "jupyter", "kernels")}

	if plat == core.PlatformWSL {
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			baseDirs = append(baseDirs, filepath.Join(winHome, "AppData", "Roaming", "jupyter", "kernels"))
		}
	}

	if plat == core.PlatformWindows || plat == core.PlatformWSL {
		if appdata := core.GetAppData(); appdata != "" {
			baseDirs = append(baseDirs, filepath.Join(appdata, "jupyter", "kernels"))
		}
	}

	if plat == core.PlatformMacOS {
		baseDirs = append(baseDirs, filepath.Join(home, "Library", "Jupyter", "kernels"))
	}

	for _, base := range baseDirs {
		info, err := os.Stat(base)
		if err != nil || !info.IsDir() {
			continue
		}
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			kj := filepath.Join(base, entry.Name(), "kernel.json")
			if _, err := os.Stat(kj); err == nil {
				kernelFiles = append(kernelFiles, kj)
			}
		}
	}
	return kernelFiles
}

func (s *jupyterScanner) scanPyConfig(path string, result *core.ScanResult, showSecrets bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	perms := core.GetFilePermissions(path)
	owner := core.GetFileOwner(path)
	storage := core.PlaintextFile

	content := string(data)
	matches := jupyterPyConfigRe.FindAllStringSubmatch(content, -1)

	for _, m := range matches {
		field := strings.ToLower(m[1])
		value := m[3]

		notes := []string{fmt.Sprintf("Jupyter %s set in Python config", field)}
		if mtime := core.GetFileMtimeTime(path); !mtime.IsZero() {
			notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
		}

		var risk core.RiskLevel
		var preview string
		var rawValue string
		if value == "" {
			notes = append(notes, "Value is EMPTY — the Jupyter server accepts connections without authentication")
			risk = core.RiskCritical
			preview = "<empty>"
			rawValue = ""
		} else {
			risk = core.AssessRisk(storage, path)
			preview = core.MaskValue(value, showSecrets)
			if showSecrets {
				rawValue = value
			}
		}

		result.Findings = append(result.Findings, core.CredentialFinding{
			ToolName:        s.Name(),
			CredentialType:  fmt.Sprintf("jupyter_%s", field),
			StorageType:     storage,
			Location:        path,
			Exists:          true,
			RiskLevel:       risk,
			ValuePreview:    preview,
			RawValue:        rawValue,
			FilePermissions: perms,
			FileOwner:       owner,
			FileModified:    core.GetFileMtime(path),
			Remediation:     jupyterTokenRemediation,
			RemediationHint: remediation.HintChangeConfigValue(field, "<strong-random-string>", path),
			Notes:           notes,
		})
	}
}

func (s *jupyterScanner) scanJSONConfig(path string, result *core.ScanResult, showSecrets bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}

	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("Failed to parse %s: %v", path, err))
		return
	}

	perms := core.GetFilePermissions(path)
	owner := core.GetFileOwner(path)
	storage := core.PlaintextJSON

	for _, sectionName := range []string{"NotebookApp", "ServerApp", "Notebook"} {
		sectionRaw, ok := data[sectionName]
		if !ok {
			continue
		}
		section, ok := sectionRaw.(map[string]interface{})
		if !ok {
			continue
		}
		for _, field := range []string{"token", "password"} {
			valRaw, ok := section[field]
			if !ok {
				continue
			}
			value, ok := valRaw.(string)
			if !ok {
				continue
			}

			notes := []string{fmt.Sprintf("Jupyter %s.%s in JSON config", sectionName, field)}
			if mtime := core.GetFileMtimeTime(path); !mtime.IsZero() {
				notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
			}

			var risk core.RiskLevel
			var preview string
			var rawValue string
			if value == "" {
				notes = append(notes, "Value is EMPTY — the Jupyter server accepts connections without authentication")
				risk = core.RiskCritical
				preview = "<empty>"
				rawValue = ""
			} else {
				risk = core.AssessRisk(storage, path)
				preview = core.MaskValue(value, showSecrets)
				if showSecrets {
					rawValue = value
				}
			}

			result.Findings = append(result.Findings, core.CredentialFinding{
				ToolName:        s.Name(),
				CredentialType:  fmt.Sprintf("jupyter_%s", field),
				StorageType:     storage,
				Location:        path,
				Exists:          true,
				RiskLevel:       risk,
				ValuePreview:    preview,
				RawValue:        rawValue,
				FilePermissions: perms,
				FileOwner:       owner,
				FileModified:    core.GetFileMtime(path),
				Remediation:     jupyterTokenRemediation,
				RemediationHint: remediation.HintChangeConfigValue(field, "<strong-random-string>", path),
				Notes:           notes,
			})
		}
	}
}

func (s *jupyterScanner) scanKernelJSON(path string, result *core.ScanResult, showSecrets bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}

	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return
	}

	envRaw, ok := data["env"]
	if !ok {
		return
	}
	env, ok := envRaw.(map[string]interface{})
	if !ok {
		return
	}

	perms := core.GetFilePermissions(path)
	owner := core.GetFileOwner(path)
	mtime := core.GetFileMtime(path)
	storage := core.PlaintextJSON
	kernelName := filepath.Base(filepath.Dir(path))

	stalenessNote := ""
	if mt := core.GetFileMtimeTime(path); !mt.IsZero() {
		stalenessNote = "File last modified: " + core.DescribeStaleness(mt)
	}

	for envKey, envValRaw := range env {
		envValue, ok := envValRaw.(string)
		if !ok {
			continue
		}
		if !jupyterLooksLikeSecret(envKey, envValue) {
			continue
		}

		notes := []string{
			fmt.Sprintf("Kernel: %s", kernelName),
			fmt.Sprintf("Env var: %s", envKey),
		}
		if stalenessNote != "" {
			notes = append(notes, stalenessNote)
		}

		rawValue := ""
		if showSecrets {
			rawValue = envValue
		}

		result.Findings = append(result.Findings, core.CredentialFinding{
			ToolName:        s.Name(),
			CredentialType:  fmt.Sprintf("kernel_env:%s", envKey),
			StorageType:     storage,
			Location:        path,
			Exists:          true,
			RiskLevel:       core.AssessRisk(storage, path),
			ValuePreview:    core.MaskValue(envValue, showSecrets),
			RawValue:        rawValue,
			FilePermissions: perms,
			FileOwner:       owner,
			FileModified:    mtime,
			Remediation:     jupyterKernelRemediation,
			RemediationHint: remediation.HintMigrateToEnv([]string{}, path),
			Notes:           notes,
		})
	}
}

func jupyterLooksLikeSecret(key, value string) bool {
	keyLower := strings.ToLower(key)
	for _, kw := range jupyterSecretKeywords {
		if strings.Contains(keyLower, kw) {
			return true
		}
	}

	if len(value) > 20 && !strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "http") {
		alnum := 0
		for _, c := range value {
			if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
				alnum++
			}
		}
		ratio := float64(alnum) / float64(len(value))
		if ratio > 0.8 {
			return true
		}
	}
	return false
}
