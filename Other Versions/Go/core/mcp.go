package core

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"unicode"
)

// secretKeyPatterns are keywords that indicate an env var or value contains a secret.
var secretKeyPatterns = []string{
	"token", "key", "secret", "password", "passwd", "auth",
	"credential", "cred", "api_key", "apikey", "access_key",
	"bearer", "jwt",
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

// ParseMCPConfig parses mcpServers from a tool's config and finds embedded credentials.
func ParseMCPConfig(data map[string]interface{}, sourcePath string, toolName string, showSecrets bool) []CredentialFinding {
	var findings []CredentialFinding

	mcpServersRaw, ok := data["mcpServers"]
	if !ok {
		return findings
	}
	mcpServers, ok := mcpServersRaw.(map[string]interface{})
	if !ok {
		return findings
	}

	perms := GetFilePermissions(sourcePath)
	owner := GetFileOwner(sourcePath)

	for serverName, serverConfigRaw := range mcpServers {
		serverConfig, ok := serverConfigRaw.(map[string]interface{})
		if !ok {
			continue
		}

		// Check env block for secrets
		if envRaw, ok := serverConfig["env"]; ok {
			if env, ok := envRaw.(map[string]interface{}); ok {
				for key, valRaw := range env {
					value, ok := valRaw.(string)
					if !ok {
						continue
					}

					if isEnvVarReference(value) {
						findings = append(findings, CredentialFinding{
							ToolName:       toolName,
							CredentialType: fmt.Sprintf("mcp_env_ref:%s", key),
							StorageType:    PlaintextJSON,
							Location:       sourcePath,
							Exists:         true,
							RiskLevel:      RiskInfo,
							ValuePreview:   value,
							Notes: []string{
								fmt.Sprintf("MCP server: %s", serverName),
								"References environment variable (not inline secret)",
							},
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
							Notes: []string{
								fmt.Sprintf("MCP server: %s", serverName),
								"Inline secret in config",
							},
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
								ToolName:       toolName,
								CredentialType: fmt.Sprintf("mcp_header:%s", key),
								StorageType:    PlaintextJSON,
								Location:       sourcePath,
								Exists:         true,
								RiskLevel:      RiskInfo,
								ValuePreview:   value,
								Notes: []string{
									fmt.Sprintf("MCP server: %s", serverName),
									"References environment variable",
								},
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
								Notes: []string{
									fmt.Sprintf("MCP server: %s", serverName),
									"Inline auth header",
								},
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
							Notes: []string{
								fmt.Sprintf("MCP server: %s", serverName),
								fmt.Sprintf("Token in CLI arg position %d", i),
							},
						})
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
