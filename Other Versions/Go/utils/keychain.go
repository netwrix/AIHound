// Package utils provides platform-specific credential access utilities.
package utils

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"aihound/core"
)

// KeychainEntry represents a single entry from the macOS Keychain.
type KeychainEntry struct {
	Service string
	Account string
}

// QueryKeychain queries the macOS Keychain for a credential by service name.
// Returns the password/token value if found, or an error otherwise.
// Only works on macOS.
func QueryKeychain(service string) (string, error) {
	if core.DetectPlatform() != core.PlatformMacOS {
		return "", ErrNotMacOS
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "security", "find-generic-password", "-s", service, "-w")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(output)), nil
}

// ListKeychainEntries lists Keychain entries, optionally filtered by service name.
// Only works on macOS.
func ListKeychainEntries(serviceFilter string) ([]KeychainEntry, error) {
	if core.DetectPlatform() != core.PlatformMacOS {
		return nil, ErrNotMacOS
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "security", "dump-keychain")
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var entries []KeychainEntry
	var current KeychainEntry
	hasData := false

	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, `"svce"`) {
			if val := extractKeychainValue(line); val != "" {
				current.Service = val
				hasData = true
			}
		} else if strings.HasPrefix(line, `"acct"`) {
			if val := extractKeychainValue(line); val != "" {
				current.Account = val
				hasData = true
			}
		} else if line == "attributes:" {
			if hasData && (serviceFilter == "" || strings.Contains(current.Service, serviceFilter)) {
				entries = append(entries, current)
			}
			current = KeychainEntry{}
			hasData = false
		}
	}

	// Don't forget the last entry.
	if hasData && (serviceFilter == "" || strings.Contains(current.Service, serviceFilter)) {
		entries = append(entries, current)
	}

	return entries, nil
}

// extractKeychainValue extracts the value from a Keychain dump line such as
// "svce"<blob>="My Service".
func extractKeychainValue(line string) string {
	idx := strings.Index(line, `="`)
	if idx < 0 {
		return ""
	}
	val := line[idx+2:]
	return strings.TrimRight(val, `"`)
}
