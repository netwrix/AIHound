// Package remediation builds structured machine-readable remediation hints.
//
// Every CredentialFinding can carry a RemediationHint dict alongside its
// human-readable Remediation string. AI assistants (via MCP) read the
// structured hint and execute fixes using their own filesystem tools.
//
// Hint schema: a freeform map keyed by an "action" string. Known actions:
//
//	chmod                  - args: [mode, path]
//	migrate_to_env         - env_vars: []string, source: path
//	change_config_value    - target: string, new_value, source: path
//	run_command            - commands: []string, shell: string
//	use_credential_helper  - tool: string, helper_options: []string
//	rotate_credential      - provider: string, description: string
//	manual                 - description: string (plus any extra fields)
//
// Scanners use these helpers instead of constructing maps inline. Mirrors the
// Python aihound.remediation module field-for-field so the on-wire JSON shape
// is identical for MCP/JSON consumers regardless of which language ran the scan.
package remediation

// HintChmod restricts file permissions, e.g. `chmod 600 /path/to/file`.
func HintChmod(mode, path string) map[string]any {
	return map[string]any{
		"action": "chmod",
		"args":   []string{mode, path},
	}
}

// HintMigrateToEnv moves a secret out of a file into one or more env vars.
func HintMigrateToEnv(envVars []string, source string) map[string]any {
	// Defensive copy so caller mutations don't bleed into the hint
	cp := make([]string, len(envVars))
	copy(cp, envVars)
	return map[string]any{
		"action":   "migrate_to_env",
		"env_vars": cp,
		"source":   source,
	}
}

// HintChangeConfigValue updates a config field. `target` is a dotted path
// (e.g. "server.host").
func HintChangeConfigValue(target string, newValue any, source string) map[string]any {
	return map[string]any{
		"action":    "change_config_value",
		"target":    target,
		"new_value": newValue,
		"source":    source,
	}
}

// HintRunCommand runs shell commands. `shell` is "bash", "powershell", or "cmd".
func HintRunCommand(commands []string, shell string) map[string]any {
	if shell == "" {
		shell = "bash"
	}
	cp := make([]string, len(commands))
	copy(cp, commands)
	return map[string]any{
		"action":   "run_command",
		"shell":    shell,
		"commands": cp,
	}
}

// HintUseCredentialHelper switches to an OS-native credential helper.
func HintUseCredentialHelper(tool string, helperOptions []string) map[string]any {
	cp := make([]string, len(helperOptions))
	copy(cp, helperOptions)
	return map[string]any{
		"action":         "use_credential_helper",
		"tool":           tool,
		"helper_options": cp,
	}
}

// HintRotateCredential is an external action — the hint just tells the AI
// where to direct the user.
func HintRotateCredential(provider, description string) map[string]any {
	return map[string]any{
		"action":      "rotate_credential",
		"provider":    provider,
		"description": description,
	}
}

// HintManual is the generic fallback when no structured action applies.
// Extra key/value pairs are merged into the result.
func HintManual(description string, extra ...map[string]any) map[string]any {
	d := map[string]any{
		"action":      "manual",
		"description": description,
	}
	for _, m := range extra {
		for k, v := range m {
			d[k] = v
		}
	}
	return d
}

// HintNetworkBind is a specialized change_config_value: rebind a service
// from 0.0.0.0 to 127.0.0.1. `path` and `port` are optional context.
func HintNetworkBind(service, path string, port int) map[string]any {
	hint := map[string]any{
		"action":    "change_config_value",
		"target":    "bind_address",
		"new_value": "127.0.0.1",
		"service":   service,
	}
	if path != "" {
		hint["source"] = path
	}
	if port > 0 {
		hint["port"] = port
	}
	return hint
}
