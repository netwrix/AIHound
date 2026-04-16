package core

import "fmt"

// StorageType describes how a credential is stored.
type StorageType int

const (
	StorageUnknown StorageType = iota
	PlaintextJSON
	PlaintextYAML
	PlaintextENV
	PlaintextINI
	PlaintextFile
	StorageKeychain
	StorageCredentialManager
	EncryptedDB
	EnvironmentVar
)

func (s StorageType) String() string {
	switch s {
	case StorageUnknown:
		return "unknown"
	case PlaintextJSON:
		return "plaintext_json"
	case PlaintextYAML:
		return "plaintext_yaml"
	case PlaintextENV:
		return "plaintext_env"
	case PlaintextINI:
		return "plaintext_ini"
	case PlaintextFile:
		return "plaintext_file"
	case StorageKeychain:
		return "keychain"
	case StorageCredentialManager:
		return "credential_manager"
	case EncryptedDB:
		return "encrypted_db"
	case EnvironmentVar:
		return "environment_var"
	default:
		return fmt.Sprintf("StorageType(%d)", int(s))
	}
}

// RiskLevel indicates the severity of a credential finding.
type RiskLevel int

const (
	RiskInfo RiskLevel = iota
	RiskLow
	RiskMedium
	RiskHigh
	RiskCritical
)

func (r RiskLevel) String() string {
	switch r {
	case RiskInfo:
		return "info"
	case RiskLow:
		return "low"
	case RiskMedium:
		return "medium"
	case RiskHigh:
		return "high"
	case RiskCritical:
		return "critical"
	default:
		return fmt.Sprintf("RiskLevel(%d)", int(r))
	}
}

// Platform represents the detected operating system.
type Platform int

const (
	PlatformLinux Platform = iota
	PlatformMacOS
	PlatformWindows
	PlatformWSL
)

func (p Platform) String() string {
	switch p {
	case PlatformLinux:
		return "linux"
	case PlatformMacOS:
		return "macos"
	case PlatformWindows:
		return "windows"
	case PlatformWSL:
		return "wsl"
	default:
		return fmt.Sprintf("Platform(%d)", int(p))
	}
}

// CredentialFinding represents a single discovered credential.
type CredentialFinding struct {
	ToolName        string
	CredentialType  string
	StorageType     StorageType
	Location        string
	Exists          bool
	RiskLevel       RiskLevel
	ValuePreview    string
	RawValue        string
	FilePermissions string
	FileOwner       string
	Expiry          string         // ISO 8601 string, empty if no expiry
	FileModified    string         // ISO 8601 string, empty if unknown
	Remediation     string         // Human-readable guidance on how to fix
	RemediationHint map[string]any // Machine-readable fix hint for AI/MCP consumers (nil if none)
	Notes           []string
}

// ScanResult holds the output of a single scanner run.
type ScanResult struct {
	ScannerName string
	Platform    string
	Findings    []CredentialFinding
	Errors      []string
	ScanTime    float64
}

// Scanner is the interface that all credential scanners must implement.
type Scanner interface {
	Name() string
	Slug() string
	IsApplicable() bool
	Scan(showSecrets bool) ScanResult
}
