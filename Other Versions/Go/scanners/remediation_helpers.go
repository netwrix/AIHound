package scanners

import (
	"aihound/core"
	"aihound/remediation"
)

// chmodRemediation returns a human-readable chmod 600 remediation string,
// but only if the file doesn't already have owner-only permissions.
func chmodRemediation(path string) string {
	if core.IsOwnerOnly(path) {
		return "File permissions are already restricted to owner-only"
	}
	return "Restrict file permissions: chmod 600 " + path
}

// chmodRemediationHint returns a structured remediation hint for chmod 600,
// or nil if the file already has owner-only permissions.
func chmodRemediationHint(path string) map[string]any {
	if core.IsOwnerOnly(path) {
		return nil
	}
	return remediation.HintChmod("600", path)
}
