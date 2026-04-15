package core

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var (
	cachedPlatform Platform
	platformOnce   sync.Once
)

// DetectPlatform detects the current OS, distinguishing WSL from native Linux.
func DetectPlatform() Platform {
	platformOnce.Do(func() {
		switch runtime.GOOS {
		case "windows":
			cachedPlatform = PlatformWindows
		case "darwin":
			cachedPlatform = PlatformMacOS
		case "linux":
			cachedPlatform = PlatformLinux
			data, err := os.ReadFile("/proc/version")
			if err == nil && strings.Contains(strings.ToLower(string(data)), "microsoft") {
				cachedPlatform = PlatformWSL
			}
		default:
			cachedPlatform = PlatformLinux
		}
	})
	return cachedPlatform
}

// GetHome returns the user's home directory.
func GetHome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return home
}

// GetAppData returns the Windows %APPDATA% path. Works on Windows and WSL.
func GetAppData() string {
	plat := DetectPlatform()

	if plat == PlatformWindows {
		if v := os.Getenv("APPDATA"); v != "" {
			return v
		}
		return filepath.Join(GetHome(), "AppData", "Roaming")
	}

	if plat == PlatformWSL {
		return FindWSLAppData()
	}

	return ""
}

// GetLocalAppData returns the Windows %LOCALAPPDATA% path. Works on Windows and WSL.
func GetLocalAppData() string {
	plat := DetectPlatform()

	if plat == PlatformWindows {
		if v := os.Getenv("LOCALAPPDATA"); v != "" {
			return v
		}
		return filepath.Join(GetHome(), "AppData", "Local")
	}

	if plat == PlatformWSL {
		appdata := FindWSLAppData()
		if appdata != "" {
			return filepath.Join(filepath.Dir(appdata), "Local")
		}
	}

	return ""
}

// GetXDGConfig returns XDG_CONFIG_HOME, defaulting to ~/.config.
func GetXDGConfig() string {
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		return v
	}
	return filepath.Join(GetHome(), ".config")
}

// GetWSLWindowsHome returns the Windows user home directory when running under WSL.
func GetWSLWindowsHome() string {
	if DetectPlatform() != PlatformWSL {
		return ""
	}

	mntC := "/mnt/c/Users"
	entries, err := os.ReadDir(mntC)
	if err != nil {
		return ""
	}

	skip := map[string]bool{
		"Public":       true,
		"Default":      true,
		"Default User": true,
		"All Users":    true,
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if skip[entry.Name()] {
			continue
		}
		candidate := filepath.Join(mntC, entry.Name())
		if info, err := os.Stat(filepath.Join(candidate, "AppData")); err == nil && info.IsDir() {
			return candidate
		}
	}

	return ""
}

// FindWSLAppData locates Windows AppData/Roaming from WSL via /mnt/c/Users/.
func FindWSLAppData() string {
	mntC := "/mnt/c/Users"
	entries, err := os.ReadDir(mntC)
	if err != nil {
		return ""
	}

	skip := map[string]bool{
		"Public":       true,
		"Default":      true,
		"Default User": true,
		"All Users":    true,
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if skip[entry.Name()] {
			continue
		}
		appdata := filepath.Join(mntC, entry.Name(), "AppData", "Roaming")
		if info, err := os.Stat(appdata); err == nil && info.IsDir() {
			return appdata
		}
	}

	return ""
}
