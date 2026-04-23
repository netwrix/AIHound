package scanners

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"aihound/core"
	"aihound/remediation"
)

// Compiled regex patterns for shell RC file scanning.
var (
	// bash/zsh: export VAR="value" or export VAR=value
	rcExportRe = regexp.MustCompile(`(?m)^export\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']?([^\s"'\n]+)["']?`)

	// fish: set -gx VAR value  or  set -x VAR value
	rcFishSetRe = regexp.MustCompile(`(?m)^set\s+(?:-[a-zA-Z]+\s+)*([A-Za-z_][A-Za-z0-9_]*)\s+["']?([^\s"'\n]+)["']?`)

	// PowerShell: $env:VAR = "value"
	rcPSEnvRe = regexp.MustCompile(`(?m)^\$env:([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']?([^\s"'\n]+)["']?`)

	// .env file: VAR=value (no export prefix)
	rcDotenvRe = regexp.MustCompile(`(?m)^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']?([^\s"'\n]+)["']?`)

	// Raw known-prefix token anywhere on a line
	rcRawTokenRe   *regexp.Regexp
	rcRawTokenOnce sync.Once
)

func rcInitRawTokenRegex() {
	rcRawTokenOnce.Do(func() {
		prefixes := core.GetKnownPrefixes()
		escaped := make([]string, len(prefixes))
		for i, p := range prefixes {
			escaped[i] = regexp.QuoteMeta(p)
		}
		prefixAlt := strings.Join(escaped, "|")
		rcRawTokenRe = regexp.MustCompile(
			`(?:^|[^A-Za-z0-9_\-])((?:` + prefixAlt + `)[A-Za-z0-9_\-./+=]{16,})`,
		)
	})
}

type shellRcScanner struct{}

func init() {
	Register(&shellRcScanner{})
}

func (s *shellRcScanner) Name() string      { return "Shell RC Files" }
func (s *shellRcScanner) Slug() string       { return "shell-rc" }
func (s *shellRcScanner) IsApplicable() bool { return true }

func (s *shellRcScanner) Scan(showSecrets bool) core.ScanResult {
	rcInitRawTokenRegex()
	plat := core.DetectPlatform()
	result := core.ScanResult{ScannerName: s.Name(), Platform: plat.String()}

	// Scan shell RC files
	for _, p := range s.getRCPaths(plat) {
		s.scanFile(p, &result, showSecrets)
	}

	// Scan .env files
	for _, p := range s.getEnvPaths(plat) {
		s.scanFile(p, &result, showSecrets)
	}

	return result
}

func (s *shellRcScanner) getRCPaths(plat core.Platform) []string {
	home := core.GetHome()
	var paths []string

	if plat == core.PlatformLinux || plat == core.PlatformMacOS || plat == core.PlatformWSL {
		// bash
		paths = append(paths, filepath.Join(home, ".bashrc"))
		paths = append(paths, filepath.Join(home, ".bash_profile"))
		paths = append(paths, filepath.Join(home, ".profile"))
		// zsh
		paths = append(paths, filepath.Join(home, ".zshrc"))
		paths = append(paths, filepath.Join(home, ".zprofile"))
		paths = append(paths, filepath.Join(home, ".zshenv"))
		// fish
		paths = append(paths, filepath.Join(home, ".config", "fish", "config.fish"))
	}

	if plat == core.PlatformWindows {
		// PowerShell profiles
		paths = append(paths,
			filepath.Join(home, "Documents", "PowerShell", "Microsoft.PowerShell_profile.ps1"),
			filepath.Join(home, "Documents", "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"),
		)
	}

	if plat == core.PlatformWSL {
		// Also scan Windows-side PowerShell profiles
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			paths = append(paths,
				filepath.Join(winHome, "Documents", "PowerShell", "Microsoft.PowerShell_profile.ps1"),
				filepath.Join(winHome, "Documents", "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"),
			)
		}
	}

	return paths
}

func (s *shellRcScanner) getEnvPaths(plat core.Platform) []string {
	home := core.GetHome()
	paths := []string{
		filepath.Join(home, ".env"),
		filepath.Join(home, ".config", ".env"),
		filepath.Join(home, ".docker", ".env"),
		filepath.Join(home, ".config", "fish", ".env"),
		filepath.Join(home, ".local", ".env"),
	}

	if plat == core.PlatformWSL {
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			paths = append(paths, filepath.Join(winHome, ".env"))
		}
	}

	return paths
}

func (s *shellRcScanner) isEnvFile(path string) bool {
	base := filepath.Base(path)
	return base == ".env" || filepath.Ext(path) == ".env"
}

func (s *shellRcScanner) scanFile(path string, result *core.ScanResult, showSecrets bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to read %s: %s", path, err))
		}
		return
	}

	text := string(raw)
	for _, f := range s.scanContent(text, path, showSecrets) {
		result.Findings = append(result.Findings, f)
	}
}

func (s *shellRcScanner) scanContent(text, path string, showSecrets bool) []core.CredentialFinding {
	var findings []core.CredentialFinding
	seenValues := map[string]bool{}

	isEnv := s.isEnvFile(path)
	storage := core.PlaintextFile
	if isEnv {
		storage = core.PlaintextENV
	}

	// Determine which assignment patterns to apply based on file type
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToLower(filepath.Base(path))
	isPS := ext == ".ps1"
	isFish := strings.Contains(path, "fish") && strings.HasSuffix(base, ".fish")

	var assignmentPatterns []*regexp.Regexp
	if isEnv {
		assignmentPatterns = []*regexp.Regexp{rcDotenvRe}
	} else if isPS {
		assignmentPatterns = []*regexp.Regexp{rcPSEnvRe}
	} else if isFish {
		assignmentPatterns = []*regexp.Regexp{rcFishSetRe, rcExportRe}
	} else {
		// bash/zsh/profile: export pattern + dotenv as fallback
		assignmentPatterns = []*regexp.Regexp{rcExportRe, rcDotenvRe}
	}

	lines := strings.Split(text, "\n")

	// Pass 1: Variable assignment patterns
	for _, pattern := range assignmentPatterns {
		for _, loc := range pattern.FindAllStringSubmatchIndex(text, -1) {
			varName := text[loc[2]:loc[3]]
			value := strings.Trim(text[loc[4]:loc[5]], "'\"")

			// Only flag if var is a known AI env var OR value matches a known prefix
			_, isAIVar := AIEnvVars[varName]
			if !isAIVar && core.IdentifyCredentialType(value) == "" {
				continue
			}

			if seenValues[value] {
				continue
			}
			seenValues[value] = true

			lineNum := strings.Count(text[:loc[0]], "\n") + 1
			lineText := ""
			if lineNum-1 < len(lines) {
				lineText = lines[lineNum-1]
			}

			credType := ""
			if desc, ok := AIEnvVars[varName]; ok {
				credType = desc
			}
			if credType == "" {
				credType = core.IdentifyCredentialType(value)
			}
			if credType == "" {
				credType = "api-key"
			}

			findings = append(findings, s.makeFinding(path, value, lineNum, lineText, credType, storage, showSecrets))
		}
	}

	// Pass 2: Raw known-prefix tokens anywhere on any line
	for _, loc := range rcRawTokenRe.FindAllStringSubmatchIndex(text, -1) {
		value := text[loc[2]:loc[3]]
		if seenValues[value] {
			continue
		}
		seenValues[value] = true

		lineNum := strings.Count(text[:loc[0]], "\n") + 1
		lineText := ""
		if lineNum-1 < len(lines) {
			lineText = lines[lineNum-1]
		}

		credType := core.IdentifyCredentialType(value)
		if credType == "" {
			credType = "api-key"
		}

		findings = append(findings, s.makeFinding(path, value, lineNum, lineText, credType, storage, showSecrets))
	}

	return findings
}

func (s *shellRcScanner) makeFinding(
	path, value string, lineNum int, lineText, credType string,
	storage core.StorageType, showSecrets bool,
) core.CredentialFinding {
	perms := core.GetFilePermissions(path)
	owner := core.GetFileOwner(path)
	mtime := core.GetFileMtime(path)
	mtimeTime := core.GetFileMtimeTime(path)

	truncated := lineText
	if len(truncated) > 120 {
		truncated = truncated[:120]
	}
	notes := []string{fmt.Sprintf("Line %d: %s", lineNum, truncated)}
	if !mtimeTime.IsZero() {
		notes = append(notes, "File last modified: "+core.DescribeStaleness(mtimeTime))
	}

	risk := core.AssessRisk(storage, path)

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
		FilePermissions: perms,
		FileOwner:       owner,
		FileModified:    mtime,
		Remediation:     "Remove credentials from shell config files. Use a secret manager or source a gitignored file instead.",
		RemediationHint: remediation.HintManual(
			"Remove credential from shell config and use a secret manager",
			map[string]any{"suggested_tools": []string{"1Password CLI", "doppler", "vault"}},
		),
		Notes: notes,
	}
}
