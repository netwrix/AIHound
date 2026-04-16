package scanners

import (
	"os"
	"path/filepath"
	"strings"

	"aihound/core"
	"aihound/remediation"
)

type huggingfaceScanner struct{}

func init() {
	Register(&huggingfaceScanner{})
}

func (s *huggingfaceScanner) Name() string        { return "Hugging Face CLI" }
func (s *huggingfaceScanner) Slug() string         { return "huggingface" }
func (s *huggingfaceScanner) IsApplicable() bool   { return true }

func (s *huggingfaceScanner) Scan(showSecrets bool) core.ScanResult {
	result := core.ScanResult{ScannerName: s.Name(), Platform: core.DetectPlatform().String()}
	plat := core.DetectPlatform()

	for _, p := range s.getTokenPaths(plat) {
		s.scanTokenFile(p, &result, showSecrets)
	}

	return result
}

func (s *huggingfaceScanner) getTokenPaths(plat core.Platform) []string {
	var paths []string
	home := core.GetHome()
	paths = append(paths,
		filepath.Join(home, ".cache", "huggingface", "token"),
		filepath.Join(home, ".huggingface", "token"),
	)

	if plat == core.PlatformWSL {
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			paths = append(paths,
				filepath.Join(winHome, ".cache", "huggingface", "token"),
				filepath.Join(winHome, ".huggingface", "token"),
			)
		}
	}
	return paths
}

func (s *huggingfaceScanner) scanTokenFile(path string, result *core.ScanResult, showSecrets bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}

	value := strings.TrimSpace(string(data))
	if value == "" {
		return
	}

	perms := core.GetFilePermissions(path)
	owner := core.GetFileOwner(path)
	storage := core.PlaintextFile

	rawValue := ""
	if showSecrets {
		rawValue = value
	}

	var notes []string
	if mtime := core.GetFileMtimeTime(path); !mtime.IsZero() {
		notes = append(notes, "File last modified: "+core.DescribeStaleness(mtime))
	}

	result.Findings = append(result.Findings, core.CredentialFinding{
		ToolName:        s.Name(),
		CredentialType:  "hf_token",
		StorageType:     storage,
		Location:        path,
		Exists:          true,
		RiskLevel:       core.AssessRisk(storage, path),
		ValuePreview:    core.MaskValue(value, showSecrets),
		RawValue:        rawValue,
		FilePermissions: perms,
		FileOwner:       owner,
		FileModified:    core.GetFileMtime(path),
		Remediation:     "Use HF_TOKEN environment variable instead of plaintext token file",
		RemediationHint: remediation.HintMigrateToEnv([]string{"HF_TOKEN"}, path),
		Notes:           notes,
	})
}
