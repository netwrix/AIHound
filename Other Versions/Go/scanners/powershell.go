package scanners

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"aihound/core"
	"aihound/remediation"
)

var (
	psTokenRe   *regexp.Regexp
	psContextRe *regexp.Regexp
	psRegexOnce sync.Once
)

func psInitRegex() {
	psRegexOnce.Do(func() {
		prefixes := core.GetKnownPrefixes()
		escaped := make([]string, len(prefixes))
		for i, p := range prefixes {
			escaped[i] = regexp.QuoteMeta(p)
		}
		prefixAlt := strings.Join(escaped, "|")
		psTokenRe = regexp.MustCompile(`(?:^|[^A-Za-z0-9_\-])((?:` + prefixAlt + `)[A-Za-z0-9_\-./+=]{16,})`)

		psContextRe = regexp.MustCompile(
			`(?i)(?:(?:api[_-]?key|token|secret|password|passwd|auth[a-z_-]*|bearer)\s*[=:]\s*|` +
				`\$env:[A-Z_][A-Z0-9_]*\s*=\s*|` +
				`-H\s+["']?Authorization:\s*Bearer\s+|` +
				`-H\s+["']?x-api-key:\s*|` +
				`--api-key\s+)` +
				`["']?([A-Za-z0-9_\-./+=]{20,})["']?`,
		)
	})
}

type powershellScanner struct{}

func init() {
	Register(&powershellScanner{})
}

func (s *powershellScanner) Name() string        { return "PowerShell Logs" }
func (s *powershellScanner) Slug() string         { return "powershell" }
func (s *powershellScanner) IsApplicable() bool   { return true }

func (s *powershellScanner) Scan(showSecrets bool) core.ScanResult {
	psInitRegex()
	result := core.ScanResult{ScannerName: s.Name(), Platform: core.DetectPlatform().String()}
	plat := core.DetectPlatform()

	for _, p := range s.getLogPaths(plat) {
		s.scanLogFile(p, &result, showSecrets)
	}
	for _, p := range s.getTranscriptPaths(plat) {
		s.scanLogFile(p, &result, showSecrets)
	}

	return result
}

func (s *powershellScanner) getLogPaths(plat core.Platform) []string {
	var paths []string
	home := core.GetHome()
	paths = append(paths, filepath.Join(home, ".local", "share", "powershell", "PSReadLine", "ConsoleHost_history.txt"))
	paths = append(paths, filepath.Join(home, ".config", "powershell", "PSReadLine", "ConsoleHost_history.txt"))

	if plat == core.PlatformWindows {
		if appdata := core.GetAppData(); appdata != "" {
			paths = append(paths, filepath.Join(appdata, "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"))
		}
	}
	if plat == core.PlatformWSL {
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			paths = append(paths, filepath.Join(winHome, "AppData", "Roaming", "Microsoft", "Windows", "PowerShell", "PSReadLine", "ConsoleHost_history.txt"))
		}
	}

	return paths
}

func (s *powershellScanner) getTranscriptPaths(plat core.Platform) []string {
	home := core.GetHome()
	roots := []string{
		filepath.Join(home, "Documents"),
		filepath.Join(home, "OneDrive", "Documents"),
	}

	if plat == core.PlatformWSL {
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			roots = append(roots,
				filepath.Join(winHome, "Documents"),
				filepath.Join(winHome, "OneDrive", "Documents"),
			)
		}
	}

	var paths []string
	for _, root := range roots {
		info, err := os.Stat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		matches, err := filepath.Glob(filepath.Join(root, "PowerShell_transcript.*.txt"))
		if err != nil {
			continue
		}
		paths = append(paths, matches...)
	}
	return paths
}

const maxPSLogSize = 50 * 1024 * 1024 // 50 MB

func (s *powershellScanner) scanLogFile(path string, result *core.ScanResult, showSecrets bool) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	if info.Size() > maxPSLogSize {
		result.Errors = append(result.Errors, fmt.Sprintf("Skipped oversized history file (%d bytes): %s", info.Size(), path))
		return
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}

	perms := core.GetFilePermissions(path)
	owner := core.GetFileOwner(path)
	mtime := core.GetFileMtime(path)
	mtimeTime := core.GetFileMtimeTime(path)
	storage := core.PlaintextFile

	text := string(raw)
	seenValues := map[string]bool{}

	// Pass 1: Known-prefix matches
	for lineNum, line := range strings.Split(text, "\n") {
		matches := psTokenRe.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			value := m[1]
			if seenValues[value] {
				continue
			}
			seenValues[value] = true
			s.addFinding(result, path, value, lineNum+1, line, perms, owner, mtime, mtimeTime, storage, showSecrets, "known-prefix")
		}
	}

	// Pass 2: Context-based matches
	for lineNum, line := range strings.Split(text, "\n") {
		matches := psContextRe.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			value := m[1]
			if seenValues[value] {
				continue
			}
			if !psLooksLikeSecret(value) {
				continue
			}
			seenValues[value] = true
			s.addFinding(result, path, value, lineNum+1, line, perms, owner, mtime, mtimeTime, storage, showSecrets, "context")
		}
	}
}

func (s *powershellScanner) addFinding(
	result *core.ScanResult, path, value string, lineNum int, lineText,
	perms, owner, mtime string, mtimeTime time.Time,
	storage core.StorageType, showSecrets bool, confidence string,
) {
	credType := core.IdentifyCredentialType(value)
	if credType == "" {
		credType = "command-line-secret"
	}

	notes := []string{fmt.Sprintf("Line %d: %s", lineNum, psTruncateLine(core.RedactLine(lineText), 120))}
	if !mtimeTime.IsZero() {
		notes = append(notes, "File last modified: "+core.DescribeStaleness(mtimeTime))
	}
	if confidence == "context" {
		notes = append(notes, "Detected via context pattern (medium confidence)")
	}

	risk := core.AssessRisk(storage, path)
	if confidence == "known-prefix" && risk != core.RiskCritical {
		if risk != core.RiskInfo {
			risk = core.RiskHigh
		} else {
			risk = core.RiskMedium
		}
	}

	rawValue := ""
	if showSecrets {
		rawValue = value
	}

	result.Findings = append(result.Findings, core.CredentialFinding{
		ToolName:        "PowerShell Logs",
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
		Remediation:     "Clear PowerShell history (Remove-Item (Get-PSReadLineOption).HistorySavePath), rotate the exposed credential, and consider Set-PSReadLineOption -HistorySaveStyle SaveNothing for sessions that handle secrets",
		RemediationHint: remediation.HintRunCommand(
			[]string{
				"Remove-Item (Get-PSReadLineOption).HistorySavePath",
				"Set-PSReadLineOption -HistorySaveStyle SaveNothing",
			},
			"powershell",
		),
		Notes:           notes,
	})
}

func psTruncateLine(line string, maxLen int) string {
	fields := strings.Fields(line)
	collapsed := strings.Join(fields, " ")
	if len(collapsed) <= maxLen {
		return collapsed
	}
	return collapsed[:maxLen-3] + "..."
}

func psLooksLikeSecret(value string) bool {
	if len(value) < 20 {
		return false
	}
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "\\") ||
		strings.HasPrefix(value, ".\\") || strings.HasPrefix(value, "./") ||
		strings.HasPrefix(value, "C:") || strings.HasPrefix(value, "c:") {
		return false
	}
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") ||
		strings.HasPrefix(value, "ftp://") || strings.HasPrefix(value, "file://") {
		return false
	}
	alnum := 0
	for _, c := range value {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			alnum++
		}
	}
	ratio := float64(alnum) / float64(len(value))
	return ratio >= 0.75
}
