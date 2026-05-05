package core

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"unicode"

	"aihound/remediation"
)

// secretKeyPatterns are keywords that indicate an env var or value contains a secret.
var secretKeyPatterns = []string{
	"token", "key", "secret", "password", "passwd", "auth",
	"credential", "cred", "api_key", "apikey", "access_key",
	"bearer", "jwt",
}

// knownNonSecretKeys are env var names that are NEVER secrets — runtime/path/
// locale plumbing. Skip the secret heuristic entirely for these to suppress
// false positives like PYTHONPATH=C:\Users\... getting flagged as a credential.
// Names are matched case-insensitively. Mirrors aihound.core.mcp.KNOWN_NON_SECRET_KEYS
// in the Python source — keep the two lists in sync.
var knownNonSecretKeys = map[string]struct{}{
	// PATH-family
	"PATH": {}, "PYTHONPATH": {}, "NODE_PATH": {}, "CLASSPATH": {},
	"LD_LIBRARY_PATH": {}, "DYLD_LIBRARY_PATH": {},
	"GOPATH": {}, "GOROOT": {}, "GOBIN": {}, "CARGO_HOME": {}, "RUSTUP_HOME": {},
	// User / session identity
	"HOME": {}, "USER": {}, "USERNAME": {}, "LOGNAME": {}, "USERPROFILE": {},
	"HOMEDRIVE": {}, "HOMEPATH": {},
	// Locale / timezone
	"LANG": {}, "LANGUAGE": {}, "LC_ALL": {}, "LC_CTYPE": {}, "LC_MESSAGES": {},
	"LC_NUMERIC": {}, "LC_TIME": {}, "LC_COLLATE": {}, "LC_MONETARY": {},
	"TZ": {},
	// Temp / runtime dirs
	"TMP": {}, "TMPDIR": {}, "TEMP": {}, "XDG_RUNTIME_DIR": {}, "XDG_CACHE_HOME": {},
	"XDG_CONFIG_HOME": {}, "XDG_DATA_HOME": {},
	// Shell + display
	"SHELL": {}, "TERM": {}, "TERM_PROGRAM": {}, "PWD": {}, "OLDPWD": {},
	"DISPLAY": {}, "WAYLAND_DISPLAY": {}, "COLORTERM": {},
	// Logging / debug flags
	"DEBUG": {}, "VERBOSE": {}, "LOG_LEVEL": {}, "LOGLEVEL": {},
	"PYTHONUNBUFFERED": {}, "PYTHONDONTWRITEBYTECODE": {},
	"NODE_ENV": {}, "RUST_LOG": {}, "RUST_BACKTRACE": {},
	// Node-specific
	"NODE_OPTIONS": {}, "NPM_CONFIG_PREFIX": {},
	// CI / orchestration noise
	"CI": {}, "GITHUB_ACTIONS": {}, "RUNNER_OS": {},
	// Misc OS plumbing
	"OS": {}, "OSTYPE": {}, "MACHTYPE": {}, "PROCESSOR_ARCHITECTURE": {},
	"SYSTEMROOT": {}, "WINDIR": {}, "COMSPEC": {},
}

// isKnownNonSecretKey returns true if the env var name is in the allowlist.
// Matching is case-insensitive.
func isKnownNonSecretKey(key string) bool {
	_, ok := knownNonSecretKeys[strings.ToUpper(key)]
	return ok
}

// ParseMCPFile reads and parses an MCP config file, returning findings.
func ParseMCPFile(path string, toolName string, showSecrets bool) []CredentialFinding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil
	}

	return ParseMCPConfig(parsed, path, toolName, showSecrets)
}

// mcpBlock pairs a server map with an optional project path for context.
type mcpBlock struct {
	servers     map[string]interface{}
	projectPath string // empty for top-level
}

// collectMCPBlocks gathers all mcpServers maps: top-level and per-project.
func collectMCPBlocks(data map[string]interface{}) []mcpBlock {
	var blocks []mcpBlock

	// Top-level mcpServers
	if raw, ok := data["mcpServers"]; ok {
		if servers, ok := raw.(map[string]interface{}); ok && len(servers) > 0 {
			blocks = append(blocks, mcpBlock{servers: servers})
		}
	}

	// Per-project mcpServers (projects.<path>.mcpServers)
	if projectsRaw, ok := data["projects"]; ok {
		if projects, ok := projectsRaw.(map[string]interface{}); ok {
			for projPath, projCfgRaw := range projects {
				if projCfg, ok := projCfgRaw.(map[string]interface{}); ok {
					if raw, ok := projCfg["mcpServers"]; ok {
						if servers, ok := raw.(map[string]interface{}); ok && len(servers) > 0 {
							blocks = append(blocks, mcpBlock{servers: servers, projectPath: projPath})
						}
					}
				}
			}
		}
	}

	return blocks
}

// ParseMCPFileDedup reads and parses an MCP config file with cross-file dedup.
func ParseMCPFileDedup(path string, toolName string, showSecrets bool, seen map[string]bool) []CredentialFinding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil
	}

	return ParseMCPConfigDedup(parsed, path, toolName, showSecrets, seen)
}

// ParseMCPConfig parses mcpServers from a tool's config and finds embedded credentials.
func ParseMCPConfig(data map[string]interface{}, sourcePath string, toolName string, showSecrets bool) []CredentialFinding {
	return ParseMCPConfigDedup(data, sourcePath, toolName, showSecrets, nil)
}

// ParseMCPConfigDedup is like ParseMCPConfig but accepts a dedup set to suppress
// duplicate findings across multiple files (e.g. primary + backups).
func ParseMCPConfigDedup(data map[string]interface{}, sourcePath string, toolName string, showSecrets bool, seen map[string]bool) []CredentialFinding {
	var findings []CredentialFinding

	blocks := collectMCPBlocks(data)
	if len(blocks) == 0 {
		return findings
	}

	perms := GetFilePermissions(sourcePath)
	owner := GetFileOwner(sourcePath)
	fileMtime := GetFileMtime(sourcePath)
	mtime := GetFileMtimeTime(sourcePath)

	appendStalenessNote := func(notes []string) []string {
		if !mtime.IsZero() {
			notes = append(notes, "File last modified: "+DescribeStaleness(mtime))
		}
		return notes
	}

	for _, block := range blocks {
		for serverName, serverConfigRaw := range block.servers {
			serverConfig, ok := serverConfigRaw.(map[string]interface{})
			if !ok {
				continue
			}

			// Helper to build notes with project scope context
			buildNotes := func(extra ...string) []string {
				notes := []string{fmt.Sprintf("MCP server: %s", serverName)}
				if block.projectPath != "" {
					notes = append(notes, fmt.Sprintf("Project scope: %s", block.projectPath))
				}
				notes = append(notes, extra...)
				return appendStalenessNote(notes)
			}

			// Check env block for secrets
			if envRaw, ok := serverConfig["env"]; ok {
				if env, ok := envRaw.(map[string]interface{}); ok {
					for key, valRaw := range env {
						value, ok := valRaw.(string)
						if !ok {
							continue
						}

						// Allowlist: PATH-family / locale / shell vars are never secrets
						if isKnownNonSecretKey(key) {
							continue
						}

						// Deduplicate across files (primary + backups)
						if seen != nil {
							dedupKey := serverName + ":" + key + ":" + value
							if seen[dedupKey] {
								continue
							}
							seen[dedupKey] = true
						}

						if isEnvVarReference(value) {
							findings = append(findings, CredentialFinding{
								ToolName:        toolName,
								CredentialType:  fmt.Sprintf("mcp_env_ref:%s", key),
								StorageType:     PlaintextJSON,
								Location:        sourcePath,
								Exists:          true,
								RiskLevel:       RiskInfo,
								ValuePreview:    value,
								FileModified:    fileMtime,
								Remediation:     "Verify env var is set in a secure environment, not committed to source",
								RemediationHint: remediation.HintManual("Verify env var is set in a secure environment, not committed to source"),
								Notes:           buildNotes("References environment variable (not inline secret)"),
							})
						} else if looksLikeSecretKey(key) || looksLikeSecretValue(value) {
							findings = append(findings, CredentialFinding{
								ToolName:        toolName,
								CredentialType:  fmt.Sprintf("mcp_env:%s", key),
								StorageType:     PlaintextJSON,
								Location:        sourcePath,
								Exists:          true,
								RiskLevel:       AssessRisk(PlaintextJSON, sourcePath),
								ValuePreview:    MaskValue(value, showSecrets),
								RawValue:        rawValueIf(value, showSecrets),
								FilePermissions: perms,
								FileOwner:       owner,
								FileModified:    fileMtime,
								Remediation:     "Move secret to environment variable or secret manager",
								RemediationHint: remediation.HintMigrateToEnv([]string{}, sourcePath),
								Notes:           buildNotes("Inline secret in config"),
							})
						}
					}
				}
			}

			// Check headers block (for HTTP transport MCP servers)
			if headersRaw, ok := serverConfig["headers"]; ok {
				if headers, ok := headersRaw.(map[string]interface{}); ok {
					for key, valRaw := range headers {
						value, ok := valRaw.(string)
						if !ok {
							continue
						}
						keyLower := strings.ToLower(key)
						if keyLower == "authorization" || keyLower == "x-api-key" || keyLower == "api-key" {
							if isEnvVarReference(value) {
								findings = append(findings, CredentialFinding{
									ToolName:        toolName,
									CredentialType:  fmt.Sprintf("mcp_header:%s", key),
									StorageType:     PlaintextJSON,
									Location:        sourcePath,
									Exists:          true,
									RiskLevel:       RiskInfo,
									ValuePreview:    value,
									FileModified:    fileMtime,
									Remediation:     "Verify env var is set in a secure environment, not committed to source",
									RemediationHint: remediation.HintManual("Verify env var is set in a secure environment, not committed to source"),
									Notes:           buildNotes("References environment variable"),
								})
							} else {
								findings = append(findings, CredentialFinding{
									ToolName:        toolName,
									CredentialType:  fmt.Sprintf("mcp_header:%s", key),
									StorageType:     PlaintextJSON,
									Location:        sourcePath,
									Exists:          true,
									RiskLevel:       AssessRisk(PlaintextJSON, sourcePath),
									ValuePreview:    MaskValue(value, showSecrets),
									RawValue:        rawValueIf(value, showSecrets),
									FilePermissions: perms,
									FileOwner:       owner,
									FileModified:    fileMtime,
									Remediation:     "Move secret to environment variable or secret manager",
									RemediationHint: remediation.HintMigrateToEnv([]string{}, sourcePath),
									Notes:           buildNotes("Inline auth header"),
								})
							}
						}
					}
				}
			}

			// Check args for tokens (some MCP servers pass tokens as CLI args)
			if argsRaw, ok := serverConfig["args"]; ok {
				if args, ok := argsRaw.([]interface{}); ok {
					for i, argRaw := range args {
						arg, ok := argRaw.(string)
						if !ok {
							continue
						}
						if looksLikeSecretValue(arg) && !strings.HasPrefix(arg, "-") {
							findings = append(findings, CredentialFinding{
								ToolName:        toolName,
								CredentialType:  fmt.Sprintf("mcp_arg[%d]", i),
								StorageType:     PlaintextJSON,
								Location:        sourcePath,
								Exists:          true,
								RiskLevel:       AssessRisk(PlaintextJSON, sourcePath),
								ValuePreview:    MaskValue(arg, showSecrets),
								RawValue:        rawValueIf(arg, showSecrets),
								FilePermissions: perms,
								FileOwner:       owner,
								FileModified:    fileMtime,
								Remediation:     "Move secret to environment variable or secret manager",
								RemediationHint: remediation.HintMigrateToEnv([]string{}, sourcePath),
								Notes:           buildNotes(fmt.Sprintf("Token in CLI arg position %d", i)),
							})
						}
					}
				}
			}
		}
	}

	return findings
}

// isEnvVarReference checks if a value contains an env var reference like ${VAR_NAME}.
func isEnvVarReference(value string) bool {
	return strings.Contains(value, "${")
}

// looksLikeSecretKey checks if an env var name suggests it contains a secret.
func looksLikeSecretKey(key string) bool {
	keyLower := strings.ToLower(key)
	for _, pattern := range secretKeyPatterns {
		if strings.Contains(keyLower, pattern) {
			return true
		}
	}
	return false
}

// looksLikeSecretValue is a heuristic to detect credential-like values.
func looksLikeSecretValue(value string) bool {
	if len(value) < 20 {
		return false
	}
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "http") {
		return false
	}
	// npm scoped package names (e.g. @perplexity-ai/mcp-server) — not secrets
	if strings.HasPrefix(value, "@") && strings.Contains(value, "/") {
		return false
	}
	// Windows paths: drive letter + colon + separator (e.g. C:\foo, d:/bar).
	// Mostly alphanumeric so they pass the ratio check below — explicit reject.
	if len(value) >= 3 && unicode.IsLetter(rune(value[0])) &&
		value[1] == ':' && (value[2] == '\\' || value[2] == '/') {
		return false
	}
	alnumCount := 0
	for _, c := range value {
		if unicode.IsLetter(c) || unicode.IsDigit(c) || c == '-' || c == '_' || c == '.' {
			alnumCount++
		}
	}
	ratio := float64(alnumCount) / float64(len(value))
	return ratio > 0.8
}

// rawValueIf returns the value if showSecrets is true, otherwise empty string.
func rawValueIf(value string, showSecrets bool) string {
	if showSecrets {
		return value
	}
	return ""
}
