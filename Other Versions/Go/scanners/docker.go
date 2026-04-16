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

var dockerSecretKeyTokens = []string{"token", "secret", "key", "password", "auth"}
var dockerRegistrySubKeyTokens = []string{"token", "secret", "key", "password"}

const dockerRemediation = "Use docker credential helpers (credsStore) instead of storing tokens in config.json. See: docker login --help"

type dockerScanner struct{}

func init() {
	Register(&dockerScanner{})
}

func (s *dockerScanner) Name() string        { return "Docker" }
func (s *dockerScanner) Slug() string         { return "docker" }
func (s *dockerScanner) IsApplicable() bool   { return true }

func (s *dockerScanner) Scan(showSecrets bool) core.ScanResult {
	result := core.ScanResult{ScannerName: s.Name(), Platform: core.DetectPlatform().String()}
	plat := core.DetectPlatform()

	for _, p := range s.getConfigPaths(plat) {
		s.scanDockerConfig(p, &result, showSecrets)
	}

	return result
}

func (s *dockerScanner) getConfigPaths(plat core.Platform) []string {
	var paths []string
	home := core.GetHome()
	paths = append(paths, filepath.Join(home, ".docker", "config.json"))

	if plat == core.PlatformWSL {
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			paths = append(paths, filepath.Join(winHome, ".docker", "config.json"))
		}
	}
	return paths
}

func (s *dockerScanner) scanDockerConfig(path string, result *core.ScanResult, showSecrets bool) {
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
	mtime := core.GetFileMtime(path)
	storage := core.PlaintextJSON

	stalenessNote := ""
	if mt := core.GetFileMtimeTime(path); !mt.IsZero() {
		stalenessNote = "File last modified: " + core.DescribeStaleness(mt)
	}

	// 1) auths dict
	if authsRaw, ok := data["auths"]; ok {
		if auths, ok := authsRaw.(map[string]interface{}); ok {
			for registry, entryRaw := range auths {
				entry, ok := entryRaw.(map[string]interface{})
				if !ok {
					continue
				}

				if authB64, ok := entry["auth"].(string); ok && authB64 != "" {
					notes := []string{
						fmt.Sprintf("Registry: %s", registry),
						"Base64(user:password) stored in plaintext",
					}
					if stalenessNote != "" {
						notes = append(notes, stalenessNote)
					}
					rawValue := ""
					if showSecrets {
						rawValue = authB64
					}
					result.Findings = append(result.Findings, core.CredentialFinding{
						ToolName:        s.Name(),
						CredentialType:  fmt.Sprintf("registry_auth:%s", registry),
						StorageType:     storage,
						Location:        path,
						Exists:          true,
						RiskLevel:       core.AssessRisk(storage, path),
						ValuePreview:    core.MaskValue(authB64, showSecrets),
						RawValue:        rawValue,
						FilePermissions: perms,
						FileOwner:       owner,
						FileModified:    mtime,
						Remediation:     dockerRemediation,
						RemediationHint: remediation.HintUseCredentialHelper("docker", []string{"osxkeychain", "pass", "secretservice"}),
						Notes:           notes,
					})
				}

				if idToken, ok := entry["identitytoken"].(string); ok && idToken != "" {
					notes := []string{
						fmt.Sprintf("Registry: %s", registry),
						"Docker identity token (OAuth refresh-like)",
					}
					if stalenessNote != "" {
						notes = append(notes, stalenessNote)
					}
					rawValue := ""
					if showSecrets {
						rawValue = idToken
					}
					result.Findings = append(result.Findings, core.CredentialFinding{
						ToolName:        s.Name(),
						CredentialType:  fmt.Sprintf("registry_identitytoken:%s", registry),
						StorageType:     storage,
						Location:        path,
						Exists:          true,
						RiskLevel:       core.AssessRisk(storage, path),
						ValuePreview:    core.MaskValue(idToken, showSecrets),
						RawValue:        rawValue,
						FilePermissions: perms,
						FileOwner:       owner,
						FileModified:    mtime,
						Remediation:     dockerRemediation,
						RemediationHint: remediation.HintUseCredentialHelper("docker", []string{"osxkeychain", "pass", "secretservice"}),
						Notes:           notes,
					})
				}

				for subKey, subValRaw := range entry {
					if subKey == "auth" || subKey == "identitytoken" || subKey == "email" || subKey == "username" {
						continue
					}
					subVal, ok := subValRaw.(string)
					if !ok || len(subVal) <= 20 {
						continue
					}
					lowered := strings.ToLower(subKey)
					match := false
					for _, k := range dockerRegistrySubKeyTokens {
						if strings.Contains(lowered, k) {
							match = true
							break
						}
					}
					if !match {
						continue
					}

					notes := []string{
						fmt.Sprintf("Registry: %s", registry),
						fmt.Sprintf("Field: %s", subKey),
					}
					if stalenessNote != "" {
						notes = append(notes, stalenessNote)
					}
					rawValue := ""
					if showSecrets {
						rawValue = subVal
					}
					result.Findings = append(result.Findings, core.CredentialFinding{
						ToolName:        s.Name(),
						CredentialType:  fmt.Sprintf("registry_%s:%s", subKey, registry),
						StorageType:     storage,
						Location:        path,
						Exists:          true,
						RiskLevel:       core.AssessRisk(storage, path),
						ValuePreview:    core.MaskValue(subVal, showSecrets),
						RawValue:        rawValue,
						FilePermissions: perms,
						FileOwner:       owner,
						FileModified:    mtime,
						Remediation:     dockerRemediation,
						RemediationHint: remediation.HintUseCredentialHelper("docker", []string{"osxkeychain", "pass", "secretservice"}),
						Notes:           notes,
					})
				}
			}
		}
	}

	// 2) credsStore
	if credsStore, ok := data["credsStore"].(string); ok && credsStore != "" {
		notes := []string{
			fmt.Sprintf("Using credential helper: docker-credential-%s", credsStore),
			"Credentials stored outside config.json (likely in OS keystore)",
		}
		if stalenessNote != "" {
			notes = append(notes, stalenessNote)
		}
		result.Findings = append(result.Findings, core.CredentialFinding{
			ToolName:        s.Name(),
			CredentialType:  "credsStore",
			StorageType:     core.StorageUnknown,
			Location:        path,
			Exists:          true,
			RiskLevel:       core.RiskInfo,
			ValuePreview:    credsStore,
			FilePermissions: perms,
			FileOwner:       owner,
			FileModified:    mtime,
			Remediation:     dockerRemediation,
			RemediationHint: remediation.HintUseCredentialHelper("docker", []string{"osxkeychain", "pass", "secretservice"}),
			Notes:           notes,
		})
	}

	// 3) credHelpers
	if credHelpersRaw, ok := data["credHelpers"]; ok {
		if credHelpers, ok := credHelpersRaw.(map[string]interface{}); ok {
			for registry, helperRaw := range credHelpers {
				helper, ok := helperRaw.(string)
				if !ok {
					continue
				}
				notes := []string{
					fmt.Sprintf("Registry: %s", registry),
					fmt.Sprintf("Using credential helper: docker-credential-%s", helper),
					"Credentials stored outside config.json (likely in OS keystore)",
				}
				if stalenessNote != "" {
					notes = append(notes, stalenessNote)
				}
				result.Findings = append(result.Findings, core.CredentialFinding{
					ToolName:        s.Name(),
					CredentialType:  fmt.Sprintf("credHelper:%s", registry),
					StorageType:     core.StorageUnknown,
					Location:        path,
					Exists:          true,
					RiskLevel:       core.RiskInfo,
					ValuePreview:    helper,
					FilePermissions: perms,
					FileOwner:       owner,
					FileModified:    mtime,
					Remediation:     dockerRemediation,
					RemediationHint: remediation.HintUseCredentialHelper("docker", []string{"osxkeychain", "pass", "secretservice"}),
					Notes:           notes,
				})
			}
		}
	}

	// 4) Top-level secret-looking keys / recurse one level
	for key, val := range data {
		if key == "auths" || key == "credsStore" || key == "credHelpers" {
			continue
		}
		switch v := val.(type) {
		case string:
			if len(v) <= 20 {
				continue
			}
			lowered := strings.ToLower(key)
			match := false
			for _, k := range dockerSecretKeyTokens {
				if strings.Contains(lowered, k) {
					match = true
					break
				}
			}
			if !match {
				continue
			}
			notes := []string{fmt.Sprintf("Top-level field: %s", key)}
			if stalenessNote != "" {
				notes = append(notes, stalenessNote)
			}
			rawValue := ""
			if showSecrets {
				rawValue = v
			}
			result.Findings = append(result.Findings, core.CredentialFinding{
				ToolName:        s.Name(),
				CredentialType:  fmt.Sprintf("config:%s", key),
				StorageType:     storage,
				Location:        path,
				Exists:          true,
				RiskLevel:       core.AssessRisk(storage, path),
				ValuePreview:    core.MaskValue(v, showSecrets),
				RawValue:        rawValue,
				FilePermissions: perms,
				FileOwner:       owner,
				FileModified:    mtime,
				Remediation:     dockerRemediation,
				RemediationHint: remediation.HintUseCredentialHelper("docker", []string{"osxkeychain", "pass", "secretservice"}),
				Notes:           notes,
			})
		case map[string]interface{}:
			s.recurseForSecrets(v, path, perms, owner, mtime, result, showSecrets, key, stalenessNote, 0)
		}
	}
}

func (s *dockerScanner) recurseForSecrets(data map[string]interface{}, path, perms, owner, mtime string, result *core.ScanResult, showSecrets bool, prefix, stalenessNote string, depth int) {
	if depth > 4 {
		return
	}
	storage := core.PlaintextJSON
	for key, val := range data {
		fullKey := prefix + "." + key
		switch v := val.(type) {
		case map[string]interface{}:
			s.recurseForSecrets(v, path, perms, owner, mtime, result, showSecrets, fullKey, stalenessNote, depth+1)
		case string:
			if len(v) <= 20 {
				continue
			}
			lowered := strings.ToLower(key)
			match := false
			for _, k := range dockerSecretKeyTokens {
				if strings.Contains(lowered, k) {
					match = true
					break
				}
			}
			if !match {
				continue
			}
			notes := []string{fmt.Sprintf("Nested field: %s", fullKey)}
			if stalenessNote != "" {
				notes = append(notes, stalenessNote)
			}
			rawValue := ""
			if showSecrets {
				rawValue = v
			}
			result.Findings = append(result.Findings, core.CredentialFinding{
				ToolName:        s.Name(),
				CredentialType:  fmt.Sprintf("config:%s", fullKey),
				StorageType:     storage,
				Location:        path,
				Exists:          true,
				RiskLevel:       core.AssessRisk(storage, path),
				ValuePreview:    core.MaskValue(v, showSecrets),
				RawValue:        rawValue,
				FilePermissions: perms,
				FileOwner:       owner,
				FileModified:    mtime,
				Remediation:     dockerRemediation,
				RemediationHint: remediation.HintUseCredentialHelper("docker", []string{"osxkeychain", "pass", "secretservice"}),
				Notes:           notes,
			})
		}
	}
}
