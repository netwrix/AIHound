package core

import "sort"

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
