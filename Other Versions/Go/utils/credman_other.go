//go:build !windows

package utils

// QueryCredentialManager is not available on non-Windows platforms.
func QueryCredentialManager(target string) (string, error) {
	return "", ErrNotWindows
}
