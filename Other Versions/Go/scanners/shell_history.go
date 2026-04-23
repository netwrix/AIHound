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
	shTokenRe   *regexp.Regexp
	shContextRe *regexp.Regexp
	shRegexOnce sync.Once
)

func shInitRegex() {
	shRegexOnce.Do(func() {
		prefixes := core.GetKnownPrefixes()
		escaped := make([]string, len(prefixes))
		for i, p := range prefixes {
			escaped[i] = regexp.QuoteMeta(p)
		}
		prefixAlt := strings.Join(escaped, "|")

		// Pass 1: Known-prefix pattern -- high confidence
		shTokenRe = regexp.MustCompile(
			`(?:^|[^A-Za-z0-9_\-])((?:` + prefixAlt + `)[A-Za-z0-9_\-./+=]{16,})`,
		)

		// Pass 2: Context-based pattern -- medium confidence
		shContextRe = regexp.MustCompile(
			`(?i)(?:(?:api[_-]?key|token|secret|password|passwd|auth[a-z_-]*|bearer)\s*[=:]\s*|` +
				`export\s+[A-Z_][A-Z0-9_]*\s*=\s*|` +
				`-H\s+["']?Authorization:\s*Bearer\s+|` +
				`-H\s+["']?x-api-key:\s*|` +
				`--api-key\s+|` +
				`--token\s+)` +
				`["']?([A-Za-z0-9_\-./+=]{20,})["']?`,
		)
	})
}

// Per-shell remediation configuration.
type shellRemediation struct {
	commands []string
	shell    string
	human    string
}

var shellRemediations = map[string]shellRemediation{
	"bash": {
		commands: []string{"rm ~/.bash_history", "history -c"},
		shell:    "bash",
		human: "Clear bash history (rm ~/.bash_history && history -c), rotate the exposed credential, " +
			"and consider HISTIGNORE for future sessions",
	},
	"zsh": {
		commands: []string{"rm ~/.zsh_history", "fc -p /dev/null"},
		shell:    "zsh",
		human: "Clear zsh history (rm ~/.zsh_history), rotate the exposed credential, " +
			"and consider setopt HIST_IGNORE_SPACE for future sessions",
	},
	"fish": {
		commands: []string{"rm ~/.local/share/fish/fish_history", "builtin history clear"},
		shell:    "fish",
		human: "Clear fish history (rm ~/.local/share/fish/fish_history), rotate the exposed credential, " +
			"and consider --private for future sessions",
	},
}

// shDetectShell detects shell type from history file path.
func shDetectShell(path string) string {
	if strings.Contains(path, "fish") {
		return "fish"
	}
	base := filepath.Base(path)
	if strings.Contains(base, "zsh") || base == ".zhistory" {
		return "zsh"
	}
	return "bash"
}

type shellHistoryScanner struct{}

func init() {
	Register(&shellHistoryScanner{})
}

func (s *shellHistoryScanner) Name() string      { return "Shell History" }
func (s *shellHistoryScanner) Slug() string       { return "shell-history" }
func (s *shellHistoryScanner) IsApplicable() bool { return true }

func (s *shellHistoryScanner) Scan(showSecrets bool) core.ScanResult {
	shInitRegex()
	plat := core.DetectPlatform()
	result := core.ScanResult{ScannerName: s.Name(), Platform: plat.String()}

	// Skip on Windows -- PowerShell scanner covers it
	if plat == core.PlatformWindows {
		return result
	}

	for _, p := range s.getHistoryPaths() {
		s.scanHistoryFile(p, &result, showSecrets)
	}

	return result
}

func (s *shellHistoryScanner) getHistoryPaths() []string {
	home := core.GetHome()
	paths := []string{
		filepath.Join(home, ".bash_history"),
		filepath.Join(home, ".zsh_history"),
		filepath.Join(home, ".zhistory"),
		filepath.Join(home, ".local", "share", "fish", "fish_history"),
	}

	// Respect ZDOTDIR for zsh
	if zdotdir := os.Getenv("ZDOTDIR"); zdotdir != "" {
		zdotHist := filepath.Join(zdotdir, ".zsh_history")
		// Avoid duplicates
		found := false
		for _, p := range paths {
			if p == zdotHist {
				found = true
				break
			}
		}
		if !found {
			paths = append(paths, zdotHist)
		}
	}

	return paths
}

func (s *shellHistoryScanner) scanHistoryFile(path string, result *core.ScanResult, showSecrets bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		// File doesn't exist -- not an error
		if !os.IsNotExist(err) {
			result.Errors = append(result.Errors, fmt.Sprintf("Failed to read %s: %s", path, err))
		}
		return
	}

	shell := shDetectShell(path)
	storage := core.PlaintextFile

	perms := core.GetFilePermissions(path)
	owner := core.GetFileOwner(path)
	mtime := core.GetFileMtime(path)
	mtimeTime := core.GetFileMtimeTime(path)

	text := string(raw)
	seenValues := map[string]bool{}

	// Pass 1: Known-prefix matches -- high confidence
	for lineNum, line := range strings.Split(text, "\n") {
		matches := shTokenRe.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			value := m[1]
			if seenValues[value] {
				continue
			}
			seenValues[value] = true
			s.addFinding(result, path, value, lineNum+1, line, perms, owner, mtime, mtimeTime, storage, showSecrets, "known-prefix", shell)
		}
	}

	// Pass 2: Context-based matches -- medium confidence
	for lineNum, line := range strings.Split(text, "\n") {
		matches := shContextRe.FindAllStringSubmatch(line, -1)
		for _, m := range matches {
			value := m[1]
			if seenValues[value] {
				continue
			}
			if !shLooksLikeSecret(value) {
				continue
			}
			seenValues[value] = true
			s.addFinding(result, path, value, lineNum+1, line, perms, owner, mtime, mtimeTime, storage, showSecrets, "context", shell)
		}
	}
}

func (s *shellHistoryScanner) addFinding(
	result *core.ScanResult, path, value string, lineNum int, lineText,
	perms, owner, mtime string, mtimeTime time.Time,
	storage core.StorageType, showSecrets bool, confidence, shell string,
) {
	credType := core.IdentifyCredentialType(value)
	if credType == "" {
		credType = "command-line-secret"
	}

	notes := []string{fmt.Sprintf("Line %d: %s", lineNum, shTruncateLine(lineText, 120))}
	if !mtimeTime.IsZero() {
		notes = append(notes, "File last modified: "+core.DescribeStaleness(mtimeTime))
	}
	if confidence == "context" {
		notes = append(notes, "Detected via context pattern (medium confidence)")
	}

	risk := core.AssessRisk(storage, path)
	// Bump to HIGH minimum for known-prefix matches (almost certainly real creds)
	if confidence == "known-prefix" && risk != core.RiskCritical && risk != core.RiskHigh {
		risk = core.RiskHigh
	}

	remCfg := shellRemediations[shell]
	if remCfg.shell == "" {
		remCfg = shellRemediations["bash"]
	}

	rawValue := ""
	if showSecrets {
		rawValue = value
	}

	result.Findings = append(result.Findings, core.CredentialFinding{
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
		Remediation:     remCfg.human,
		RemediationHint: remediation.HintRunCommand(remCfg.commands, remCfg.shell),
		Notes:           notes,
	})
}

func shTruncateLine(line string, maxLen int) string {
	fields := strings.Fields(line)
	collapsed := strings.Join(fields, " ")
	if len(collapsed) <= maxLen {
		return collapsed
	}
	return collapsed[:maxLen-3] + "..."
}

func shLooksLikeSecret(value string) bool {
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
