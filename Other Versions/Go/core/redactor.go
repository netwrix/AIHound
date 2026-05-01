package core

import (
	"regexp"
	"sort"
	"strings"
	"sync"
)

// knownPrefix maps a credential prefix to its human-readable type name.
type knownPrefix struct {
	Prefix string
	Name   string
}

// knownPrefixes is sorted longest-first for correct matching.
var knownPrefixes []knownPrefix

func init() {
	raw := []knownPrefix{
		{"sk-ant-ort", "Anthropic Refresh Token"},
		{"sk-ant-oat", "Anthropic Access Token"},
		{"sk-ant-", "Anthropic API Key"},
		{"sk-", "OpenAI/Generic API Key"},
		{"github_pat_", "GitHub PAT (fine-grained)"},
		{"ghp_", "GitHub PAT (classic)"},
		{"gho_", "GitHub OAuth Token"},
		{"ghu_", "GitHub User-to-Server Token"},
		{"ghs_", "GitHub Server-to-Server Token"},
		{"xoxb-", "Slack Bot Token"},
		{"xoxp-", "Slack User Token"},
		{"xoxa-", "Slack App Token"},
		{"AKIA", "AWS Access Key"},
		{"AIza", "Google API Key"},
		{"ya29.", "Google OAuth Access Token"},
	}
	// Sort by prefix length descending for longest-prefix-first matching
	sort.Slice(raw, func(i, j int) bool {
		return len(raw[i].Prefix) > len(raw[j].Prefix)
	})
	knownPrefixes = raw
}

// findMatchingPrefix returns the prefix string and type name for a value,
// or empty strings if no known prefix matches.
func findMatchingPrefix(value string) (string, string) {
	for _, kp := range knownPrefixes {
		if len(value) >= len(kp.Prefix) && value[:len(kp.Prefix)] == kp.Prefix {
			return kp.Prefix, kp.Name
		}
	}
	return "", ""
}

// MaskValue masks a credential value, preserving known prefixes and last 4 chars.
// If showFull is true, the value is returned unchanged.
func MaskValue(value string, showFull bool) string {
	if showFull {
		return value
	}

	if value == "" || len(value) <= 8 {
		return "***REDACTED***"
	}

	prefix, _ := findMatchingPrefix(value)
	if prefix != "" {
		// Show prefix + up to 4 extra chars + ... + last 4
		extra := len(value) - len(prefix) - 4
		if extra > 4 {
			extra = 4
		}
		var previewStart string
		if extra > 0 {
			previewStart = value[:len(prefix)+extra]
		} else {
			previewStart = value[:len(prefix)]
		}
		return previewStart + "..." + value[len(value)-4:]
	}

	// No known prefix: show first 6 + ... + last 4
	return value[:6] + "..." + value[len(value)-4:]
}

// IdentifyCredentialType tries to identify what kind of credential a value is
// based on its prefix. Returns empty string if unrecognized.
func IdentifyCredentialType(value string) string {
	_, name := findMatchingPrefix(value)
	return name
}

// GetKnownPrefixes returns the list of known credential prefixes,
// sorted longest-first (for regex alternation construction).
func GetKnownPrefixes() []string {
	out := make([]string, 0, len(knownPrefixes))
	for _, kp := range knownPrefixes {
		out = append(out, kp.Prefix)
	}
	return out
}

// redactLineRe matches known-prefix tokens in a line of text.
// Built once on first call to RedactLine.
var (
	redactLineRe   *regexp.Regexp
	redactValueRe  *regexp.Regexp
	redactLineOnce sync.Once
)

func initRedactRegex() {
	redactLineOnce.Do(func() {
		prefixes := GetKnownPrefixes()
		escaped := make([]string, len(prefixes))
		for i, p := range prefixes {
			escaped[i] = regexp.QuoteMeta(p)
		}
		prefixAlt := strings.Join(escaped, "|")
		// Match known-prefix tokens (prefix + 16+ alphanum chars)
		redactLineRe = regexp.MustCompile(`((?:` + prefixAlt + `)[A-Za-z0-9_\-./+=]{16,})`)
		// Match values after = signs and similar assignment patterns
		redactValueRe = regexp.MustCompile(`(?i)((?:api[_-]?key|token|secret|password|passwd|auth[a-z_-]*|bearer)\s*[=:]\s*["']?)([A-Za-z0-9_\-./+=]{20,})`)
	})
}

// RedactLine masks known credential patterns in a line of text intended for
// notes or log output. Known-prefix tokens are replaced with prefix + "***".
// Values after common assignment patterns (e.g. "token=...") are replaced
// with "***REDACTED***".
func RedactLine(line string) string {
	initRedactRegex()

	// Pass 1: Redact known-prefix tokens
	line = redactLineRe.ReplaceAllStringFunc(line, func(match string) string {
		prefix, _ := findMatchingPrefix(match)
		if prefix != "" {
			return prefix + "***"
		}
		if len(match) > 6 {
			return match[:6] + "***"
		}
		return "***REDACTED***"
	})

	// Pass 2: Redact values after assignment patterns
	line = redactValueRe.ReplaceAllString(line, "${1}***REDACTED***")

	return line
}
