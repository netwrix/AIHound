package scanners

import (
	"path/filepath"

	"aihound/core"
)

type cursorScanner struct{}

func init() {
	Register(&cursorScanner{})
}

func (s *cursorScanner) Name() string      { return "Cursor IDE" }
func (s *cursorScanner) Slug() string       { return "cursor" }
func (s *cursorScanner) IsApplicable() bool { return true }

func (s *cursorScanner) Scan(showSecrets bool) core.ScanResult {
	result := core.ScanResult{ScannerName: s.Name(), Platform: core.DetectPlatform().String()}
	plat := core.DetectPlatform()

	for _, p := range s.getMCPPaths(plat) {
		findings := core.ParseMCPFile(p, s.Name(), showSecrets)
		result.Findings = append(result.Findings, findings...)
	}

	return result
}

func (s *cursorScanner) getMCPPaths(plat core.Platform) []string {
	var paths []string
	home := core.GetHome()

	// ~/.cursor/mcp.json
	paths = append(paths, filepath.Join(home, ".cursor", "mcp.json"))

	switch plat {
	case core.PlatformMacOS:
		paths = append(paths,
			filepath.Join(home, "Library", "Application Support", "Cursor", "User", "globalStorage", "mcp.json"),
		)
	case core.PlatformWindows:
		if appdata := core.GetAppData(); appdata != "" {
			paths = append(paths,
				filepath.Join(appdata, "Cursor", "User", "globalStorage", "mcp.json"),
			)
		}
	case core.PlatformLinux:
		paths = append(paths,
			filepath.Join(core.GetXDGConfig(), "Cursor", "User", "globalStorage", "mcp.json"),
		)
	case core.PlatformWSL:
		paths = append(paths,
			filepath.Join(core.GetXDGConfig(), "Cursor", "User", "globalStorage", "mcp.json"),
		)
		if winHome := core.GetWSLWindowsHome(); winHome != "" {
			paths = append(paths, filepath.Join(winHome, ".cursor", "mcp.json"))
		}
		if appdata := core.GetAppData(); appdata != "" {
			paths = append(paths,
				filepath.Join(appdata, "Cursor", "User", "globalStorage", "mcp.json"),
			)
		}
	}

	return paths
}
