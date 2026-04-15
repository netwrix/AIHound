package scanners

import (
	"path/filepath"

	"aihound/core"
)

type clineScanner struct{}

func init() {
	Register(&clineScanner{})
}

func (s *clineScanner) Name() string      { return "Cline (VS Code)" }
func (s *clineScanner) Slug() string       { return "cline" }
func (s *clineScanner) IsApplicable() bool { return true }

func (s *clineScanner) Scan(showSecrets bool) core.ScanResult {
	result := core.ScanResult{ScannerName: s.Name(), Platform: core.DetectPlatform().String()}
	plat := core.DetectPlatform()

	for _, p := range s.getMCPSettingsPaths(plat) {
		findings := core.ParseMCPFile(p, s.Name(), showSecrets)
		result.Findings = append(result.Findings, findings...)
	}

	return result
}

func (s *clineScanner) getMCPSettingsPaths(plat core.Platform) []string {
	var paths []string
	extensionID := "saoudrizwan.claude-dev"
	settingsFile := filepath.Join("settings", "cline_mcp_settings.json")

	switch plat {
	case core.PlatformMacOS:
		base := filepath.Join(core.GetHome(), "Library", "Application Support", "Code", "User", "globalStorage", extensionID)
		paths = append(paths, filepath.Join(base, settingsFile))

	case core.PlatformWindows:
		if appdata := core.GetAppData(); appdata != "" {
			base := filepath.Join(appdata, "Code", "User", "globalStorage", extensionID)
			paths = append(paths, filepath.Join(base, settingsFile))
		}

	case core.PlatformLinux:
		base := filepath.Join(core.GetXDGConfig(), "Code", "User", "globalStorage", extensionID)
		paths = append(paths, filepath.Join(base, settingsFile))

	case core.PlatformWSL:
		base := filepath.Join(core.GetXDGConfig(), "Code", "User", "globalStorage", extensionID)
		paths = append(paths, filepath.Join(base, settingsFile))
		if appdata := core.GetAppData(); appdata != "" {
			winBase := filepath.Join(appdata, "Code", "User", "globalStorage", extensionID)
			paths = append(paths, filepath.Join(winBase, settingsFile))
		}
	}

	return paths
}
