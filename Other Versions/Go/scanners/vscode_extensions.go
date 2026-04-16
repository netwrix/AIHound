package scanners

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"aihound/core"
	"aihound/remediation"
)

var vscodeExcludedExtensions = map[string]bool{
	"github.copilot":        true,
	"github.copilot-chat":   true,
	"saoudrizwan.claude-dev": true, // Cline
}

const vscodeMaxJSONSize = 1024 * 1024 // 1 MB
const vscodeMaxDirDepth = 3
const vscodeMaxJSONDepth = 8

var vscodeSecretKeySubstrings = []string{"token", "key", "secret", "password", "apikey", "auth"}

const vscodeRemediation = "Use VS Code's SecretStorage API or OS keychain for extension credentials"

type vscodeExtensionsScanner struct{}

func init() {
	Register(&vscodeExtensionsScanner{})
}

func (s *vscodeExtensionsScanner) Name() string        { return "VS Code Extensions" }
func (s *vscodeExtensionsScanner) Slug() string         { return "vscode-extensions" }
func (s *vscodeExtensionsScanner) IsApplicable() bool   { return true }

func (s *vscodeExtensionsScanner) Scan(showSecrets bool) core.ScanResult {
	result := core.ScanResult{ScannerName: s.Name(), Platform: core.DetectPlatform().String()}
	plat := core.DetectPlatform()

	for _, base := range s.getGlobalStorageRoots(plat) {
		s.scanGlobalStorage(base, &result, showSecrets)
	}

	return result
}

func (s *vscodeExtensionsScanner) getGlobalStorageRoots(plat core.Platform) []string {
	var roots []string

	if plat == core.PlatformLinux || plat == core.PlatformWSL {
		roots = append(roots, filepath.Join(core.GetXDGConfig(), "Code", "User", "globalStorage"))
	}
	if plat == core.PlatformMacOS {
		roots = append(roots, filepath.Join(core.GetHome(), "Library", "Application Support", "Code", "User", "globalStorage"))
	}
	if plat == core.PlatformWindows {
		if appdata := core.GetAppData(); appdata != "" {
			roots = append(roots, filepath.Join(appdata, "Code", "User", "globalStorage"))
		}
	}

	if plat == core.PlatformWSL {
		if appdata := core.GetAppData(); appdata != "" {
			roots = append(roots, filepath.Join(appdata, "Code", "User", "globalStorage"))
		}
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			roots = append(roots, filepath.Join(winHome, "AppData", "Roaming", "Code", "User", "globalStorage"))
		}
	}

	// De-duplicate
	seen := map[string]bool{}
	var unique []string
	for _, r := range roots {
		if !seen[r] {
			seen[r] = true
			unique = append(unique, r)
		}
	}
	return unique
}

func (s *vscodeExtensionsScanner) scanGlobalStorage(base string, result *core.ScanResult, showSecrets bool) {
	info, err := os.Stat(base)
	if err != nil || !info.IsDir() {
		return
	}

	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		extID := entry.Name()
		if vscodeExcludedExtensions[extID] {
			continue
		}

		extDir := filepath.Join(base, extID)
		jsonFiles := s.iterJSONFiles(extDir, 0)
		for _, jf := range jsonFiles {
			s.scanExtensionJSON(jf, extID, result, showSecrets)
		}
	}
}

func (s *vscodeExtensionsScanner) iterJSONFiles(directory string, depth int) []string {
	if depth > vscodeMaxDirDepth {
		return nil
	}
	children, err := os.ReadDir(directory)
	if err != nil {
		return nil
	}

	var out []string
	for _, child := range children {
		childPath := filepath.Join(directory, child.Name())
		if child.IsDir() {
			out = append(out, s.iterJSONFiles(childPath, depth+1)...)
			continue
		}
		if strings.ToLower(filepath.Ext(child.Name())) != ".json" {
			continue
		}
		info, err := child.Info()
		if err != nil || info.Size() > vscodeMaxJSONSize {
			continue
		}
		out = append(out, childPath)
	}
	return out
}

func (s *vscodeExtensionsScanner) scanExtensionJSON(path, extensionID string, result *core.ScanResult, showSecrets bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}

	var data interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return
	}

	perms := core.GetFilePermissions(path)
	owner := core.GetFileOwner(path)
	mtime := core.GetFileMtime(path)

	stalenessNote := ""
	if mt := core.GetFileMtimeTime(path); !mt.IsZero() {
		stalenessNote = "File last modified: " + core.DescribeStaleness(mt)
	}

	storage := core.PlaintextJSON

	walkOut := s.walk(data, "", 0)
	for _, entry := range walkOut {
		value, ok := entry.value.(string)
		if !ok {
			continue
		}

		leaf := entry.keyPath
		if idx := strings.LastIndex(entry.keyPath, "."); idx >= 0 {
			leaf = entry.keyPath[idx+1:]
		}
		leafLower := strings.ToLower(leaf)
		matched := false
		for _, sub := range vscodeSecretKeySubstrings {
			if strings.Contains(leafLower, sub) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}

		if !vscodeValueLooksSecret(value) {
			continue
		}

		notes := []string{
			fmt.Sprintf("Extension: %s", extensionID),
			fmt.Sprintf("JSON path: %s", entry.keyPath),
		}
		if stalenessNote != "" {
			notes = append(notes, stalenessNote)
		}

		rawValue := ""
		if showSecrets {
			rawValue = value
		}

		result.Findings = append(result.Findings, core.CredentialFinding{
			ToolName:        s.Name(),
			CredentialType:  fmt.Sprintf("%s:%s", extensionID, entry.keyPath),
			StorageType:     storage,
			Location:        path,
			Exists:          true,
			RiskLevel:       core.AssessRisk(storage, path),
			ValuePreview:    core.MaskValue(value, showSecrets),
			RawValue:        rawValue,
			FilePermissions: perms,
			FileOwner:       owner,
			FileModified:    mtime,
			Remediation:     vscodeRemediation,
			RemediationHint: remediation.HintManual(vscodeRemediation),
			Notes:           notes,
		})
	}
}

type vscodeWalkEntry struct {
	keyPath string
	value   interface{}
}

func (s *vscodeExtensionsScanner) walk(data interface{}, prefix string, depth int) []vscodeWalkEntry {
	if depth > vscodeMaxJSONDepth {
		return nil
	}
	var out []vscodeWalkEntry

	switch v := data.(type) {
	case map[string]interface{}:
		for k, val := range v {
			newPrefix := k
			if prefix != "" {
				newPrefix = prefix + "." + k
			}
			switch val.(type) {
			case map[string]interface{}, []interface{}:
				out = append(out, s.walk(val, newPrefix, depth+1)...)
			default:
				out = append(out, vscodeWalkEntry{keyPath: newPrefix, value: val})
			}
		}
	case []interface{}:
		for i, val := range v {
			newPrefix := fmt.Sprintf("[%d]", i)
			if prefix != "" {
				newPrefix = fmt.Sprintf("%s[%d]", prefix, i)
			}
			switch val.(type) {
			case map[string]interface{}, []interface{}:
				out = append(out, s.walk(val, newPrefix, depth+1)...)
			default:
				out = append(out, vscodeWalkEntry{keyPath: newPrefix, value: val})
			}
		}
	}
	return out
}

func vscodeValueLooksSecret(value string) bool {
	if len(value) < 20 {
		return false
	}
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "\\") ||
		strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") ||
		strings.HasPrefix(value, "file://") {
		return false
	}
	if strings.Contains(value, " ") {
		return false
	}
	// alnum + -_.~+/=
	allowed := 0
	for _, c := range value {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' || c == '+' || c == '/' || c == '=' {
			allowed++
		}
	}
	ratio := float64(allowed) / float64(len(value))
	return ratio >= 0.8
}
