"""Scanner for AI-related environment variables."""

from __future__ import annotations

import os

from aihound.core.scanner import (
    BaseScanner,
    CredentialFinding,
    ScanResult,
    StorageType,
    RiskLevel,
)
from aihound.core.platform import detect_platform
from aihound.core.redactor import mask_value, identify_credential_type
from aihound.remediation import hint_manual
from aihound.scanners import register

# Known AI-related environment variables and their descriptions
AI_ENV_VARS = {
    # Anthropic / Claude
    "ANTHROPIC_API_KEY": "Anthropic API key",
    "ANTHROPIC_AUTH_TOKEN": "Anthropic auth token (Bearer)",
    "CLAUDE_CODE_OAUTH_TOKEN": "Claude Code long-lived OAuth token",
    "CLAUDE_CODE_USE_BEDROCK": "Claude Code Bedrock flag (indicates AWS auth)",
    "CLAUDE_CODE_USE_VERTEX": "Claude Code Vertex flag (indicates GCP auth)",
    "CLAUDE_CODE_USE_FOUNDRY": "Claude Code Foundry flag",
    # OpenAI
    "OPENAI_API_KEY": "OpenAI API key",
    "OPENAI_ORG_ID": "OpenAI organization ID",
    # Google
    "GEMINI_API_KEY": "Google Gemini API key",
    "GOOGLE_API_KEY": "Google API key",
    "GOOGLE_APPLICATION_CREDENTIALS": "Google service account key file path",
    # GitHub
    "GITHUB_TOKEN": "GitHub token",
    "GH_TOKEN": "GitHub CLI token",
    "GITHUB_PERSONAL_ACCESS_TOKEN": "GitHub personal access token",
    "COPILOT_GITHUB_TOKEN": "GitHub Copilot token",
    # AWS
    "AWS_ACCESS_KEY_ID": "AWS access key ID",
    "AWS_SECRET_ACCESS_KEY": "AWS secret access key",
    "AWS_SESSION_TOKEN": "AWS session token",
    "AWS_PROFILE": "AWS profile name",
    # Azure
    "ADO_MCP_AUTH_TOKEN": "Azure DevOps MCP auth token",
    "AZURE_OPENAI_API_KEY": "Azure OpenAI API key",
    "AZURE_OPENAI_ENDPOINT": "Azure OpenAI endpoint",
    # Misc AI
    "HUGGING_FACE_HUB_TOKEN": "Hugging Face Hub token",
    "HF_TOKEN": "Hugging Face token",
    "COHERE_API_KEY": "Cohere API key",
    "REPLICATE_API_TOKEN": "Replicate API token",
    "TOGETHER_API_KEY": "Together AI API key",
    "GROQ_API_KEY": "Groq API key",
    "MISTRAL_API_KEY": "Mistral AI API key",
    "DEEPSEEK_API_KEY": "DeepSeek API key",
    "XAI_API_KEY": "xAI/Grok API key",
    "PERPLEXITY_API_KEY": "Perplexity API key",
    "FIREWORKS_API_KEY": "Fireworks AI API key",
    # Ollama
    "OLLAMA_API_KEY": "Ollama API key (auth proxy)",
    # LM Studio
    "LM_STUDIO_API_KEY": "LM Studio API key",
}


@register
class EnvVarScanner(BaseScanner):
    def name(self) -> str:
        return "Environment Variables"

    def slug(self) -> str:
        return "envvars"

    def scan(self, show_secrets: bool = False) -> ScanResult:
        plat = detect_platform()
        result = ScanResult(scanner_name=self.name(), platform=plat.value)

        for var_name, description in AI_ENV_VARS.items():
            value = os.environ.get(var_name)
            if value:
                # Skip non-secret flags
                if var_name in ("CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX",
                                "CLAUDE_CODE_USE_FOUNDRY", "AWS_PROFILE"):
                    result.findings.append(CredentialFinding(
                        tool_name=self.name(),
                        credential_type=description,
                        storage_type=StorageType.ENVIRONMENT_VAR,
                        location=f"${var_name}",
                        exists=True,
                        risk_level=RiskLevel.INFO,
                        value_preview=value,
                        notes=["Configuration flag, not a secret"],
                    ))
                    continue

                # Path references aren't secrets themselves
                if var_name == "GOOGLE_APPLICATION_CREDENTIALS":
                    result.findings.append(CredentialFinding(
                        tool_name=self.name(),
                        credential_type=description,
                        storage_type=StorageType.ENVIRONMENT_VAR,
                        location=f"${var_name}",
                        exists=True,
                        risk_level=RiskLevel.MEDIUM,
                        value_preview=value,
                        remediation="Use a secret manager instead of environment variables",
                        remediation_hint=hint_manual(
                            "Use a secret manager instead of environment variables",
                            suggested_tools=["1Password CLI", "doppler", "vault"],
                        ),
                        notes=[f"Points to service account key file: {value}"],
                    ))
                    continue

                cred_type = identify_credential_type(value)
                notes = []
                if cred_type:
                    notes.append(f"Identified as: {cred_type}")

                result.findings.append(CredentialFinding(
                    tool_name=self.name(),
                    credential_type=description,
                    storage_type=StorageType.ENVIRONMENT_VAR,
                    location=f"${var_name}",
                    exists=True,
                    risk_level=RiskLevel.MEDIUM,
                    value_preview=mask_value(value, show_full=show_secrets),
                    raw_value=value if show_secrets else None,
                    remediation="Use a secret manager instead of environment variables",
                    remediation_hint=hint_manual(
                        "Use a secret manager instead of environment variables",
                        suggested_tools=["1Password CLI", "doppler", "vault"],
                    ),
                    notes=notes,
                ))

        return result
