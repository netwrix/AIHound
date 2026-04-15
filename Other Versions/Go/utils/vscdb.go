package utils

import (
	"database/sql"
	"path/filepath"
	"sort"
	"strings"

	"aihound/core"

	// Pure-Go SQLite driver (no CGO required).
	// Dependency: modernc.org/sqlite — add to go.mod with:
	//   go get modernc.org/sqlite
	_ "modernc.org/sqlite"
)

// GetVSCDBPaths returns the possible paths to VS Code's state.vscdb file
// for the current platform.
func GetVSCDBPaths() []string {
	plat := core.DetectPlatform()
	var paths []string

	switch plat {
	case core.PlatformLinux, core.PlatformWSL:
		cfg := core.GetXDGConfig()
		if cfg != "" {
			paths = append(paths, filepath.Join(cfg, "Code", "User", "globalStorage", "state.vscdb"))
		}
	case core.PlatformMacOS:
		home := core.GetHome()
		if home != "" {
			paths = append(paths, filepath.Join(home, "Library", "Application Support", "Code", "User", "globalStorage", "state.vscdb"))
		}
	case core.PlatformWindows:
		appdata := core.GetAppData()
		if appdata != "" {
			paths = append(paths, filepath.Join(appdata, "Code", "User", "globalStorage", "state.vscdb"))
		}
	}

	// WSL also checks the Windows-side AppData path.
	if plat == core.PlatformWSL {
		appdata := core.GetAppData()
		if appdata != "" {
			paths = append(paths, filepath.Join(appdata, "Code", "User", "globalStorage", "state.vscdb"))
		}
	}

	return paths
}

// ListSecretKeys opens the VS Code state.vscdb SQLite database and returns
// all keys from the ItemTable that begin with "secret://".
// The values are encrypted with Electron's safeStorage API and cannot be
// decrypted without the OS keychain encryption key.
func ListSecretKeys(vscdbPath string) ([]string, error) {
	db, err := sql.Open("sqlite", vscdbPath)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.Query("SELECT key FROM ItemTable WHERE key LIKE 'secret://%'")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			continue
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

// GetExtensionIDsWithSecrets returns sorted, unique extension IDs that have
// stored secrets in the given VS Code state.vscdb file.
// Secret keys have the format: secret://<extension-id>/<secret-name>
func GetExtensionIDsWithSecrets(vscdbPath string) ([]string, error) {
	keys, err := ListSecretKeys(vscdbPath)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	for _, key := range keys {
		if !strings.HasPrefix(key, "secret://") {
			continue
		}
		rest := key[len("secret://"):]
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) > 0 && parts[0] != "" {
			seen[parts[0]] = struct{}{}
		}
	}

	extensions := make([]string, 0, len(seen))
	for ext := range seen {
		extensions = append(extensions, ext)
	}
	sort.Strings(extensions)
	return extensions, nil
}
