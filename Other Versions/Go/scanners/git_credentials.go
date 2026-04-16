package scanners

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"aihound/core"
	"aihound/remediation"
)

type gitCredentialsScanner struct{}

func init() {
	Register(&gitCredentialsScanner{})
}

func (s *gitCredentialsScanner) Name() string        { return "Git Credentials" }
func (s *gitCredentialsScanner) Slug() string         { return "git-credentials" }
func (s *gitCredentialsScanner) IsApplicable() bool   { return true }

func (s *gitCredentialsScanner) Scan(showSecrets bool) core.ScanResult {
	result := core.ScanResult{ScannerName: s.Name(), Platform: core.DetectPlatform().String()}
	plat := core.DetectPlatform()

	for _, p := range s.getCredentialStorePaths(plat) {
		s.scanCredentialsFile(p, &result, showSecrets)
	}
	for _, p := range s.getGitconfigPaths(plat) {
		s.scanGitconfig(p, &result, showSecrets)
	}

	return result
}

func (s *gitCredentialsScanner) getCredentialStorePaths(plat core.Platform) []string {
	var paths []string
	home := core.GetHome()
	paths = append(paths, filepath.Join(home, ".git-credentials"))

	xdgConfig := core.GetXDGConfig()
	paths = append(paths, filepath.Join(xdgConfig, "git", "credentials"))

	if plat == core.PlatformWSL {
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			paths = append(paths, filepath.Join(winHome, ".git-credentials"))
		}
	}
	return paths
}

func (s *gitCredentialsScanner) getGitconfigPaths(plat core.Platform) []string {
	var paths []string
	home := core.GetHome()
	paths = append(paths, filepath.Join(home, ".gitconfig"))
	paths = append(paths, filepath.Join(core.GetXDGConfig(), "git", "config"))

	if plat == core.PlatformWSL {
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			paths = append(paths, filepath.Join(winHome, ".gitconfig"))
		}
	}
	return paths
}

func (s *gitCredentialsScanner) scanCredentialsFile(path string, result *core.ScanResult, showSecrets bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	perms := core.GetFilePermissions(path)
	owner := core.GetFileOwner(path)
	storage := core.PlaintextFile

	for lineNum, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parsed, err := url.Parse(line)
		if err != nil {
			continue
		}
		if parsed.Scheme == "" {
			continue
		}

		user := ""
		password := ""
		if parsed.User != nil {
			user = parsed.User.Username()
			if pw, ok := parsed.User.Password(); ok {
				password = pw
			}
		}
		if password == "" {
			continue
		}

		host := parsed.Hostname()
		if host == "" {
			host = "?"
		}
		usernameDisplay := user
		if usernameDisplay == "" {
			usernameDisplay = "(none)"
		}

		notes := []string{
			fmt.Sprintf("Host: %s", host),
			fmt.Sprintf("Username: %s", usernameDisplay),
			fmt.Sprintf("Line: %d", lineNum+1),
		}
		if mtime := core.GetFileMtimeTime(path); !mtime.IsZero() {
			notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
		}

		rawValue := ""
		if showSecrets {
			rawValue = password
		}

		result.Findings = append(result.Findings, core.CredentialFinding{
			ToolName:        s.Name(),
			CredentialType:  fmt.Sprintf("git_credential:%s", host),
			StorageType:     storage,
			Location:        path,
			Exists:          true,
			RiskLevel:       core.AssessRisk(storage, path),
			ValuePreview:    core.MaskValue(password, showSecrets),
			RawValue:        rawValue,
			FilePermissions: perms,
			FileOwner:       owner,
			FileModified:    core.GetFileMtime(path),
			Remediation:     "Use a secure credential helper (osxkeychain, manager, libsecret) instead of plaintext store",
			RemediationHint: remediation.HintUseCredentialHelper("git", []string{"osxkeychain", "manager", "libsecret"}),
			Notes:           notes,
		})
	}
}

func (s *gitCredentialsScanner) scanGitconfig(path string, result *core.ScanResult, showSecrets bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	perms := core.GetFilePermissions(path)
	owner := core.GetFileOwner(path)
	storage := core.PlaintextINI

	sections := parseINI(string(data))

	for sectionName, kvs := range sections {
		sectionLower := strings.ToLower(sectionName)

		for key, value := range kvs {
			if value == "" {
				continue
			}
			keyLower := strings.ToLower(key)

			// 1) url = https://user:token@... entry
			if keyLower == "url" {
				parsed, err := url.Parse(value)
				if err == nil && parsed.User != nil {
					if pw, ok := parsed.User.Password(); ok && pw != "" {
						host := parsed.Hostname()
						if host == "" {
							host = "?"
						}
						username := parsed.User.Username()
						usernameDisplay := username
						if usernameDisplay == "" {
							usernameDisplay = "(none)"
						}
						notes := []string{
							fmt.Sprintf("Section: [%s]", sectionName),
							fmt.Sprintf("Host: %s", host),
							fmt.Sprintf("Username: %s", usernameDisplay),
						}
						if mtime := core.GetFileMtimeTime(path); !mtime.IsZero() {
							notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
						}

						rawValue := ""
						if showSecrets {
							rawValue = pw
						}

						result.Findings = append(result.Findings, core.CredentialFinding{
							ToolName:        s.Name(),
							CredentialType:  fmt.Sprintf("gitconfig_url:%s", host),
							StorageType:     storage,
							Location:        path,
							Exists:          true,
							RiskLevel:       core.AssessRisk(storage, path),
							ValuePreview:    core.MaskValue(pw, showSecrets),
							RawValue:        rawValue,
							FilePermissions: perms,
							FileOwner:       owner,
							FileModified:    core.GetFileMtime(path),
							Remediation:     "Remove embedded credentials from gitconfig URL; use a credential helper instead",
							RemediationHint: remediation.HintUseCredentialHelper("git", []string{"osxkeychain", "manager", "libsecret"}),
							Notes:           notes,
						})
					}
				}
			}

			// 2) [credential] sections: secret-looking keys
			if strings.HasPrefix(sectionLower, "credential") {
				// Skip non-secret fields
				skipField := false
				for _, tok := range []string{"helper", "username", "usehttppath"} {
					if strings.Contains(keyLower, tok) {
						skipField = true
						break
					}
				}
				if skipField {
					continue
				}
				secretMatch := false
				for _, tok := range []string{"password", "token", "secret", "key"} {
					if strings.Contains(keyLower, tok) {
						secretMatch = true
						break
					}
				}
				if !secretMatch {
					continue
				}

				notes := []string{
					fmt.Sprintf("Section: [%s]", sectionName),
					fmt.Sprintf("Key: %s", key),
				}
				if mtime := core.GetFileMtimeTime(path); !mtime.IsZero() {
					notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
				}

				rawValue := ""
				if showSecrets {
					rawValue = value
				}

				result.Findings = append(result.Findings, core.CredentialFinding{
					ToolName:        s.Name(),
					CredentialType:  fmt.Sprintf("gitconfig_credential:%s", key),
					StorageType:     storage,
					Location:        path,
					Exists:          true,
					RiskLevel:       core.AssessRisk(storage, path),
					ValuePreview:    core.MaskValue(value, showSecrets),
					RawValue:        rawValue,
					FilePermissions: perms,
					FileOwner:       owner,
					FileModified:    core.GetFileMtime(path),
					Remediation:     "Use a secure credential helper (osxkeychain, manager, libsecret) instead of plaintext store",
					RemediationHint: remediation.HintUseCredentialHelper("git", []string{"osxkeychain", "manager", "libsecret"}),
					Notes:           notes,
				})
			}
		}
	}
}
