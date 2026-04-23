package scanners

import (
	"fmt"
	"os"

	"aihound/core"
	"aihound/remediation"
)

// AIEnvVars maps environment variable names to human-readable descriptions.
// Exported so other scanners (persistent_env, shell_rc) can reference the list.
var AIEnvVars = map[string]string{
	// Anthropic / Claude
	"ANTHROPIC_API_KEY":        "Anthropic API key",
	"ANTHROPIC_AUTH_TOKEN":     "Anthropic auth token (Bearer)",
	"CLAUDE_CODE_OAUTH_TOKEN":  "Claude Code long-lived OAuth token",
	"CLAUDE_CODE_USE_BEDROCK":  "Claude Code Bedrock flag (indicates AWS auth)",
	"CLAUDE_CODE_USE_VERTEX":   "Claude Code Vertex flag (indicates GCP auth)",
	"CLAUDE_CODE_USE_FOUNDRY":  "Claude Code Foundry flag",
	// OpenAI
	"OPENAI_API_KEY": "OpenAI API key",
	"OPENAI_ORG_ID":  "OpenAI organization ID",
	// Google
	"GEMINI_API_KEY":                 "Google Gemini API key",
	"GOOGLE_API_KEY":                 "Google API key",
	"GOOGLE_APPLICATION_CREDENTIALS": "Google service account key file path",
	// GitHub
	"GITHUB_TOKEN":                 "GitHub token",
	"GH_TOKEN":                     "GitHub CLI token",
	"GITHUB_PERSONAL_ACCESS_TOKEN": "GitHub personal access token",
	"COPILOT_GITHUB_TOKEN":         "GitHub Copilot token",
	// AWS
	"AWS_ACCESS_KEY_ID":     "AWS access key ID",
	"AWS_SECRET_ACCESS_KEY": "AWS secret access key",
	"AWS_SESSION_TOKEN":     "AWS session token",
	"AWS_PROFILE":           "AWS profile name",
	// Azure
	"ADO_MCP_AUTH_TOKEN":    "Azure DevOps MCP auth token",
	"AZURE_OPENAI_API_KEY":  "Azure OpenAI API key",
	"AZURE_OPENAI_ENDPOINT": "Azure OpenAI endpoint",
	// Misc AI
	"HUGGING_FACE_HUB_TOKEN": "Hugging Face Hub token",
	"HF_TOKEN":               "Hugging Face token",
	"COHERE_API_KEY":         "Cohere API key",
	"REPLICATE_API_TOKEN":    "Replicate API token",
	"TOGETHER_API_KEY":       "Together AI API key",
	"GROQ_API_KEY":           "Groq API key",
	"MISTRAL_API_KEY":        "Mistral AI API key",
	"DEEPSEEK_API_KEY":       "DeepSeek API key",
	"XAI_API_KEY":            "xAI/Grok API key",
	"PERPLEXITY_API_KEY":     "Perplexity API key",
	"FIREWORKS_API_KEY":      "Fireworks AI API key",
	// Ollama
	"OLLAMA_API_KEY":    "Ollama API key (auth proxy)",
	"OLLAMA_HOST":       "Ollama server bind address",
	// LM Studio
	"LM_STUDIO_API_KEY": "LM Studio API key",
}

// envVarFlags are non-secret configuration flags (INFO risk).
var envVarFlags = map[string]bool{
	"CLAUDE_CODE_USE_BEDROCK":  true,
	"CLAUDE_CODE_USE_VERTEX":   true,
	"CLAUDE_CODE_USE_FOUNDRY":  true,
	"AWS_PROFILE":              true,
}

type envVarScanner struct{}

func init() {
	Register(&envVarScanner{})
}

func (s *envVarScanner) Name() string      { return "Environment Variables" }
func (s *envVarScanner) Slug() string       { return "envvars" }
func (s *envVarScanner) IsApplicable() bool { return true }

func (s *envVarScanner) Scan(showSecrets bool) core.ScanResult {
	result := core.ScanResult{ScannerName: s.Name(), Platform: core.DetectPlatform().String()}

	for varName, description := range AIEnvVars {
		value := os.Getenv(varName)
		if value == "" {
			continue
		}

		// Non-secret flags
		if envVarFlags[varName] {
			result.Findings = append(result.Findings, core.CredentialFinding{
				ToolName:       s.Name(),
				CredentialType: description,
				StorageType:    core.EnvironmentVar,
				Location:       fmt.Sprintf("$%s", varName),
				Exists:         true,
				RiskLevel:      core.RiskInfo,
				ValuePreview:   value,
				Remediation:    "Use a secret manager instead of environment variables",
				Notes:          []string{"Configuration flag, not a secret"},
			})
			continue
		}

		// File path reference
		if varName == "GOOGLE_APPLICATION_CREDENTIALS" {
			result.Findings = append(result.Findings, core.CredentialFinding{
				ToolName:       s.Name(),
				CredentialType: description,
				StorageType:    core.EnvironmentVar,
				Location:       fmt.Sprintf("$%s", varName),
				Exists:         true,
				RiskLevel:      core.RiskMedium,
				ValuePreview:   value,
				Remediation:    "Use a secret manager instead of environment variables",
				RemediationHint: remediation.HintManual(
					"Use a secret manager instead of environment variables",
					map[string]any{"suggested_tools": []string{"1Password CLI", "doppler", "vault"}},
				),
				Notes:          []string{fmt.Sprintf("Points to service account key file: %s", value)},
			})
			continue
		}

		// Credentials
		credType := core.IdentifyCredentialType(value)
		var notes []string
		if credType != "" {
			notes = append(notes, fmt.Sprintf("Identified as: %s", credType))
		}

		rawValue := ""
		if showSecrets {
			rawValue = value
		}
		result.Findings = append(result.Findings, core.CredentialFinding{
			ToolName:       s.Name(),
			CredentialType: description,
			StorageType:    core.EnvironmentVar,
			Location:       fmt.Sprintf("$%s", varName),
			Exists:         true,
			RiskLevel:      core.RiskMedium,
			ValuePreview:   core.MaskValue(value, showSecrets),
			RawValue:       rawValue,
			Remediation:    "Use a secret manager instead of environment variables",
			RemediationHint: remediation.HintManual(
				"Use a secret manager instead of environment variables",
				map[string]any{"suggested_tools": []string{"1Password CLI", "doppler", "vault"}},
			),
			Notes:          notes,
		})
	}

	return result
}
