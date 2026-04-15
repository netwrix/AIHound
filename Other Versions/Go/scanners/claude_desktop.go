package scanners

import (
	"path/filepath"

	"aihound/core"
)

type claudeDesktopScanner struct{}

func init() {
	Register(&claudeDesktopScanner{})
}

func (s *claudeDesktopScanner) Name() string      { return "Claude Desktop" }
func (s *claudeDesktopScanner) Slug() string       { return "claude-desktop" }
func (s *claudeDesktopScanner) IsApplicable() bool { return true }

func (s *claudeDesktopScanner) Scan(showSecrets bool) core.ScanResult {
	result := core.ScanResult{ScannerName: s.Name(), Platform: core.DetectPlatform().String()}
	plat := core.DetectPlatform()

	for _, p := range s.getConfigPaths(plat) {
		findings := core.ParseMCPFile(p, s.Name(), showSecrets)
		result.Findings = append(result.Findings, findings...)
	}

	return result
}

func (s *claudeDesktopScanner) getConfigPaths(plat core.Platform) []string {
	var paths []string

	switch plat {
	case core.PlatformMacOS:
		paths = append(paths,
			filepath.Join(core.GetHome(), "Library", "Application Support", "Claude", "claude_desktop_config.json"),
		)

	case core.PlatformWindows:
		if appdata := core.GetAppData(); appdata != "" {
			paths = append(paths,
				filepath.Join(appdata, "Claude", "claude_desktop_config.json"),
			)
		}

	case core.PlatformLinux:
		paths = append(paths,
			filepath.Join(core.GetXDGConfig(), "Claude", "claude_desktop_config.json"),
		)

	case core.PlatformWSL:
		// Linux-side
		paths = append(paths,
			filepath.Join(core.GetXDGConfig(), "Claude", "claude_desktop_config.json"),
		)
		// Windows-side
		if appdata := core.GetAppData(); appdata != "" {
			paths = append(paths,
				filepath.Join(appdata, "Claude", "claude_desktop_config.json"),
			)
		}
	}

	return paths
}
