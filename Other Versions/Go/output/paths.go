package output

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// prepareOutputPath expands ~ to the user's home directory and creates any
// missing parent directories. Returns the resolved absolute path on success,
// or an error on failure.
func prepareOutputPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("empty output path")
	}

	// Expand ~ at the start of the path (Unix convention; harmless on Windows)
	if strings.HasPrefix(path, "~") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot resolve ~ (no home dir): %w", err)
		}
		if len(path) == 1 {
			path = home
		} else if path[1] == '/' || path[1] == filepath.Separator {
			path = filepath.Join(home, path[2:])
		}
	}

	// Normalize path separators on Windows
	if runtime.GOOS == "windows" {
		path = filepath.FromSlash(path)
	}

	// Auto-create parent directory
	parent := filepath.Dir(path)
	if parent != "" && parent != "." {
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return "", fmt.Errorf("cannot create directory %s: %w", parent, err)
		}
	}

	return path, nil
}
