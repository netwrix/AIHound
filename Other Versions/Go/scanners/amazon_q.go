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

type amazonQScanner struct{}

func init() {
	Register(&amazonQScanner{})
}

func (s *amazonQScanner) Name() string      { return "Amazon Q / AWS" }
func (s *amazonQScanner) Slug() string       { return "amazon-q" }
func (s *amazonQScanner) IsApplicable() bool { return true }

func (s *amazonQScanner) Scan(showSecrets bool) core.ScanResult {
	result := core.ScanResult{ScannerName: s.Name(), Platform: core.DetectPlatform().String()}
	plat := core.DetectPlatform()

	for _, path := range s.getCredentialPaths(plat) {
		s.scanAWSCredentials(path, &result, showSecrets)
	}

	for _, path := range s.getSSOCachePaths(plat) {
		s.scanSSOCache(path, &result, showSecrets)
	}

	return result
}

func (s *amazonQScanner) getCredentialPaths(plat core.Platform) []string {
	home := core.GetHome()
	paths := []string{filepath.Join(home, ".aws", "credentials")}

	if plat == core.PlatformWSL {
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			paths = append(paths, filepath.Join(winHome, ".aws", "credentials"))
		}
	}

	return paths
}

func (s *amazonQScanner) getSSOCachePaths(plat core.Platform) []string {
	home := core.GetHome()
	paths := []string{filepath.Join(home, ".aws", "sso", "cache")}

	if plat == core.PlatformWSL {
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			paths = append(paths, filepath.Join(winHome, ".aws", "sso", "cache"))
		}
	}

	return paths
}

// scanAWSCredentials parses an INI-format AWS credentials file manually.
func (s *amazonQScanner) scanAWSCredentials(path string, result *core.ScanResult, showSecrets bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}

	perms := core.GetFilePermissions(path)
	owner := core.GetFileOwner(path)
	storage := core.PlaintextINI

	// Simple manual INI parsing
	sections := parseINI(string(raw))

	awsKeys := []string{"aws_access_key_id", "aws_secret_access_key", "aws_session_token"}

	for sectionName, kvs := range sections {
		for _, key := range awsKeys {
			value, ok := kvs[key]
			if !ok || value == "" {
				continue
			}

			rawValue := ""
			if showSecrets {
				rawValue = value
			}
			notes := []string{fmt.Sprintf("AWS profile: [%s]", sectionName)}
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
				Remediation:     "Use AWS SSO or IAM roles instead of long-lived access keys",
				RemediationHint: remediation.HintManual(
					"Use AWS SSO or IAM roles instead of long-lived access keys",
					map[string]any{"suggested_commands": []string{"aws configure sso"}},
				),
				Notes:           notes,
			})
		}
	}
}

// parseINI does minimal INI parsing: [section] headers and key=value pairs.
func parseINI(content string) map[string]map[string]string {
	sections := make(map[string]map[string]string)
	currentSection := ""

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Section header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.TrimSpace(line[1 : len(line)-1])
			if _, ok := sections[currentSection]; !ok {
				sections[currentSection] = make(map[string]string)
			}
			continue
		}

		// Key=value pair
		if idx := strings.Index(line, "="); idx >= 0 && currentSection != "" {
			key := strings.TrimSpace(line[:idx])
			value := strings.TrimSpace(line[idx+1:])
			sections[currentSection][key] = value
		}
	}

	return sections
}

func (s *amazonQScanner) scanSSOCache(cacheDir string, result *core.ScanResult, showSecrets bool) {
	if _, err := os.Stat(cacheDir); err != nil {
		return
	}

	matches, _ := filepath.Glob(filepath.Join(cacheDir, "*.json"))
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

		accessToken, ok := obj["accessToken"].(string)
		if !ok || accessToken == "" {
			continue
		}

		rawValue := ""
		if showSecrets {
			rawValue = accessToken
		}
		notes := []string{"AWS SSO cached token"}
		if mtime := core.GetFileMtimeTime(jsonFile); !mtime.IsZero() {
			notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
		}
		result.Findings = append(result.Findings, core.CredentialFinding{
			ToolName:        s.Name(),
			CredentialType:  "sso_access_token",
			StorageType:     core.PlaintextJSON,
			Location:        jsonFile,
			Exists:          true,
			RiskLevel:       core.AssessRisk(core.PlaintextJSON, jsonFile),
			ValuePreview:    core.MaskValue(accessToken, showSecrets),
			RawValue:        rawValue,
			FilePermissions: perms,
			FileOwner:       owner,
			FileModified:    core.GetFileMtime(jsonFile),
			Remediation:     "Rotate SSO tokens regularly",
			RemediationHint: remediation.HintRotateCredential("aws-sso", "Rotate SSO tokens regularly"),
			Notes:           notes,
		})
	}
}
