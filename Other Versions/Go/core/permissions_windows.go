//go:build windows

package core

// GetFileOwner returns the file owner's username.
// On Windows, this is not easily available without Win32 API calls.
// Returns empty string.
func GetFileOwner(path string) string {
	return ""
}
