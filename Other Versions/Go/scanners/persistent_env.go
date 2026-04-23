package scanners

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"aihound/core"
	"aihound/remediation"
)

const maxProfileDSize = 65536 // 64KB

// Compiled regex patterns for persistent environment scanning.
var (
	// /etc/environment and environment.d: VAR=value (no "export" prefix)
	peKVRe = regexp.MustCompile(`(?m)^\s*([A-Z_][A-Z0-9_]*)\s*=\s*["']?([^"'\s#]+)["']?`)

	// profile.d / launchd.conf: export VAR=value
	peExportRe = regexp.MustCompile(`(?m)^\s*export\s+([A-Z_][A-Z0-9_]*)\s*=\s*["']?([^"'\s#]+)["']?`)

	// ~/.pam_environment: VAR DEFAULT=value  or  VAR OVERRIDE=value
	pePamRe = regexp.MustCompile(`(?m)^\s*([A-Z_][A-Z0-9_]*)\s+(?:DEFAULT|OVERRIDE)\s*=\s*["']?([^"'\s#]+)["']?`)

	// reg.exe query output:    NAME    REG_SZ    VALUE
	peRegLineRe = regexp.MustCompile(`(?m)^\s+(\S+)\s+REG_(?:SZ|EXPAND_SZ)\s+(.+)$`)
)

// peIsAIRelevant returns true if the variable name is a known AI env var
// or the value matches a known credential prefix.
func peIsAIRelevant(varName, value string) bool {
	if _, ok := AIEnvVars[varName]; ok {
		return true
	}
	if core.IdentifyCredentialType(value) != "" {
		return true
	}
	return false
}

type persistentEnvScanner struct{}

func init() {
	Register(&persistentEnvScanner{})
}

func (s *persistentEnvScanner) Name() string      { return "Persistent Environment" }
func (s *persistentEnvScanner) Slug() string       { return "persistent-env" }
func (s *persistentEnvScanner) IsApplicable() bool { return true }

func (s *persistentEnvScanner) Scan(showSecrets bool) core.ScanResult {
	plat := core.DetectPlatform()
	result := core.ScanResult{ScannerName: s.Name(), Platform: plat.String()}

	if plat == core.PlatformLinux || plat == core.PlatformWSL {
		s.scanLinux(&result, showSecrets)
	} else if plat == core.PlatformMacOS {
		s.scanMacOS(&result, showSecrets)
	} else if plat == core.PlatformWindows {
		s.scanWindowsRegistry(&result, showSecrets)
	}

	// On WSL also check the Windows registry
	if plat == core.PlatformWSL {
		s.scanWindowsRegistry(&result, showSecrets)
	}

	return result
}

// ---------------------------------------------------------------------------
// Linux / WSL scanning
// ---------------------------------------------------------------------------

func (s *persistentEnvScanner) scanLinux(result *core.ScanResult, showSecrets bool) {
	// /etc/environment -- system-wide key=value
	etcEnv := "/etc/environment"
	if text, ok := s.readFile(etcEnv, result); ok {
		for _, f := range s.scanKVContent(text, etcEnv, showSecrets, true) {
			result.Findings = append(result.Findings, f)
		}
	}

	// /etc/profile.d/*.sh -- system-wide shell scripts
	profileD := "/etc/profile.d"
	if info, err := os.Stat(profileD); err == nil && info.IsDir() {
		matches, _ := filepath.Glob(filepath.Join(profileD, "*.sh"))
		for _, shFile := range matches {
			fi, err := os.Stat(shFile)
			if err != nil {
				continue
			}
			if fi.Size() > maxProfileDSize {
				result.Errors = append(result.Errors, fmt.Sprintf("Skipped (>64KB): %s", shFile))
				continue
			}
			if text, ok := s.readFile(shFile, result); ok {
				for _, f := range s.scanExportContent(text, shFile, showSecrets, true) {
					result.Findings = append(result.Findings, f)
				}
			}
		}
	}

	// ~/.pam_environment -- user-level PAM
	home := core.GetHome()
	pamEnv := filepath.Join(home, ".pam_environment")
	if text, ok := s.readFile(pamEnv, result); ok {
		for _, f := range s.scanPamContent(text, pamEnv, showSecrets) {
			result.Findings = append(result.Findings, f)
		}
	}

	// ~/.config/environment.d/*.conf -- systemd user env
	envD := filepath.Join(home, ".config", "environment.d")
	if info, err := os.Stat(envD); err == nil && info.IsDir() {
		matches, _ := filepath.Glob(filepath.Join(envD, "*.conf"))
		for _, confFile := range matches {
			if text, ok := s.readFile(confFile, result); ok {
				for _, f := range s.scanKVContent(text, confFile, showSecrets, false) {
					result.Findings = append(result.Findings, f)
				}
			}
		}
	}
}

// ---------------------------------------------------------------------------
// macOS scanning
// ---------------------------------------------------------------------------

func (s *persistentEnvScanner) scanMacOS(result *core.ScanResult, showSecrets bool) {
	// TODO: macOS plist parsing (~/Library/LaunchAgents/*.plist,
	// /Library/LaunchDaemons/*.plist) is skipped because Go's stdlib
	// has no plistlib equivalent. Consider howett.net/plist if needed.

	// /etc/launchd.conf -- deprecated export-style
	launchdConf := "/etc/launchd.conf"
	if text, ok := s.readFile(launchdConf, result); ok {
		for _, f := range s.scanExportContent(text, launchdConf, showSecrets, true) {
			result.Findings = append(result.Findings, f)
		}
	}
}

// ---------------------------------------------------------------------------
// Windows registry scanning
// ---------------------------------------------------------------------------

func (s *persistentEnvScanner) scanWindowsRegistry(result *core.ScanResult, showSecrets bool) {
	hkcuKey := `HKCU\Environment`
	hklmKey := `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`

	if output, ok := s.queryRegistry(hkcuKey, result); ok {
		for _, f := range s.parseRegOutput(output, hkcuKey, showSecrets, false) {
			result.Findings = append(result.Findings, f)
		}
	}

	if output, ok := s.queryRegistry(hklmKey, result); ok {
		for _, f := range s.parseRegOutput(output, hklmKey, showSecrets, true) {
			result.Findings = append(result.Findings, f)
		}
	}
}

// ---------------------------------------------------------------------------
// Content parsers
// ---------------------------------------------------------------------------

func (s *persistentEnvScanner) scanKVContent(text, path string, showSecrets, isSystem bool) []core.CredentialFinding {
	var findings []core.CredentialFinding
	for _, pair := range peMatchesWithLineNumbers(text, peKVRe) {
		varName := pair.match[1]
		value := strings.TrimSpace(pair.match[2])
		if !peIsAIRelevant(varName, value) {
			continue
		}
		findings = append(findings, s.makeFileFinding(varName, value, path, pair.lineNum, showSecrets, isSystem, core.PlaintextFile))
	}
	return findings
}

func (s *persistentEnvScanner) scanExportContent(text, path string, showSecrets, isSystem bool) []core.CredentialFinding {
	var findings []core.CredentialFinding
	for _, pair := range peMatchesWithLineNumbers(text, peExportRe) {
		varName := pair.match[1]
		value := strings.TrimSpace(pair.match[2])
		if !peIsAIRelevant(varName, value) {
			continue
		}
		findings = append(findings, s.makeFileFinding(varName, value, path, pair.lineNum, showSecrets, isSystem, core.PlaintextFile))
	}
	return findings
}

func (s *persistentEnvScanner) scanPamContent(text, path string, showSecrets bool) []core.CredentialFinding {
	var findings []core.CredentialFinding
	for _, pair := range peMatchesWithLineNumbers(text, pePamRe) {
		varName := pair.match[1]
		value := strings.TrimSpace(pair.match[2])
		if !peIsAIRelevant(varName, value) {
			continue
		}
		// ~/.pam_environment is always user-level (HIGH via PlaintextENV)
		findings = append(findings, s.makeFileFinding(varName, value, path, pair.lineNum, showSecrets, false, core.PlaintextENV))
	}
	return findings
}

func (s *persistentEnvScanner) parseRegOutput(output, regKey string, showSecrets, isSystem bool) []core.CredentialFinding {
	var findings []core.CredentialFinding
	for _, m := range peRegLineRe.FindAllStringSubmatch(output, -1) {
		varName := strings.TrimSpace(m[1])
		value := strings.TrimSpace(m[2])
		if !peIsAIRelevant(varName, value) {
			continue
		}

		credType := core.IdentifyCredentialType(value)
		if credType == "" {
			if desc, ok := AIEnvVars[varName]; ok {
				credType = desc
			} else {
				credType = varName
			}
		}

		risk := core.RiskHigh
		if isSystem {
			risk = core.RiskCritical
		}

		scope := "User"
		if isSystem {
			scope = "Machine"
		}
		psCmd := fmt.Sprintf("[System.Environment]::SetEnvironmentVariable('%s', $null, '%s')", varName, scope)

		rawValue := ""
		if showSecrets {
			rawValue = value
		}

		findings = append(findings, core.CredentialFinding{
			ToolName:       s.Name(),
			CredentialType: credType,
			StorageType:    core.PlaintextINI,
			Location:       fmt.Sprintf(`%s\%s`, regKey, varName),
			Exists:         true,
			RiskLevel:      risk,
			ValuePreview:   core.MaskValue(value, showSecrets),
			RawValue:       rawValue,
			Notes:          []string{fmt.Sprintf("Registry key: %s", regKey)},
			Remediation:    "Remove credential from Windows registry environment and use a secret manager",
			RemediationHint: remediation.HintRunCommand(
				[]string{psCmd},
				"powershell",
			),
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------

func (s *persistentEnvScanner) readFile(path string, result *core.ScanResult) (string, bool) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return "", false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsPermission(err) {
			result.Errors = append(result.Errors, fmt.Sprintf("Permission denied: %s", path))
		} else {
			result.Errors = append(result.Errors, fmt.Sprintf("Could not read %s: %s", path, err))
		}
		return "", false
	}
	return string(data), true
}

func (s *persistentEnvScanner) queryRegistry(key string, result *core.ScanResult) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "reg.exe", "query", key)
	out, err := cmd.Output()
	if err != nil {
		// reg.exe not available (pure Linux) or key doesn't exist -- not an error
		if ctx.Err() == context.DeadlineExceeded {
			result.Errors = append(result.Errors, fmt.Sprintf("Timeout querying registry key: %s", key))
		}
		return "", false
	}
	return string(out), true
}

func (s *persistentEnvScanner) makeFileFinding(
	varName, value, path string, lineNum int, showSecrets, isSystem bool, storage core.StorageType,
) core.CredentialFinding {
	credType := core.IdentifyCredentialType(value)
	if credType == "" {
		if desc, ok := AIEnvVars[varName]; ok {
			credType = desc
		} else {
			credType = varName
		}
	}

	risk := core.RiskHigh
	if isSystem {
		risk = core.RiskCritical
	}

	rawValue := ""
	if showSecrets {
		rawValue = value
	}

	return core.CredentialFinding{
		ToolName:        s.Name(),
		CredentialType:  credType,
		StorageType:     storage,
		Location:        fmt.Sprintf("%s:%d", path, lineNum),
		Exists:          true,
		RiskLevel:       risk,
		ValuePreview:    core.MaskValue(value, showSecrets),
		RawValue:        rawValue,
		FilePermissions: core.GetFilePermissions(path),
		FileOwner:       core.GetFileOwner(path),
		FileModified:    core.GetFileMtime(path),
		Notes:           []string{fmt.Sprintf("Found %s at line %d in %s", varName, lineNum, path)},
		Remediation:     "Remove credential from persistent environment store and use a secret manager",
		RemediationHint: remediation.HintManual(
			"Remove credential from persistent environment store and use a secret manager",
			map[string]any{"suggested_tools": []string{"1Password CLI", "doppler", "vault"}},
		),
	}
}

// peLineMatch holds a regex submatch and its 1-based line number.
type peLineMatch struct {
	lineNum int
	match   []string // submatch groups
}

// peMatchesWithLineNumbers returns all matches with their 1-based line numbers.
func peMatchesWithLineNumbers(text string, pattern *regexp.Regexp) []peLineMatch {
	var results []peLineMatch
	for _, loc := range pattern.FindAllStringSubmatchIndex(text, -1) {
		lineNum := strings.Count(text[:loc[0]], "\n") + 1
		// Extract submatch strings
		groups := make([]string, 0, len(loc)/2)
		for i := 0; i < len(loc); i += 2 {
			if loc[i] >= 0 {
				groups = append(groups, text[loc[i]:loc[i+1]])
			} else {
				groups = append(groups, "")
			}
		}
		results = append(results, peLineMatch{lineNum: lineNum, match: groups})
	}
	return results
}
