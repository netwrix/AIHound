package utils

import "errors"

var (
	// ErrNotMacOS is returned when a macOS-only function is called on another platform.
	ErrNotMacOS = errors.New("macOS Keychain not available on this platform")

	// ErrNotWindows is returned when a Windows-only function is called on another platform.
	ErrNotWindows = errors.New("Windows Credential Manager not available on this platform")
)
