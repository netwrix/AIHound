package core

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// GetFilePermissions returns file permissions as an octal string (e.g. "0644").
// Returns empty string on error or on Windows.
func GetFilePermissions(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	mode := info.Mode().Perm()
	return fmt.Sprintf("%04o", mode)
}

// IsWorldReadable checks if a file is readable by others (o+r).
func IsWorldReadable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().Perm()&0004 != 0
}

// IsGroupReadable checks if a file is readable by group (g+r).
func IsGroupReadable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode().Perm()&0040 != 0
}

// DescribePermissions translates an octal permission string to a human-readable description.
func DescribePermissions(perms string) string {
	if perms == "" {
		return "unknown"
	}

	mode, err := strconv.ParseUint(perms, 8, 32)
	if err != nil {
		return "unknown"
	}

	var parts []string

	otherR := mode&0004 != 0
	otherW := mode&0002 != 0
	groupR := mode&0040 != 0
	groupW := mode&0020 != 0

	if otherW {
		parts = append(parts, "world-writable", "DANGEROUS")
	}
	if otherR {
		parts = append(parts, "world-readable")
	}
	if groupW && !otherW {
		parts = append(parts, "group-writable")
	}
	if groupR && !otherR {
		parts = append(parts, "group-readable")
	}
	if !groupR && !otherR && !groupW && !otherW {
		parts = append(parts, "owner-only")
	}

	if len(parts) == 0 {
		return "owner-only"
	}
	return strings.Join(parts, ", ")
}

// AssessRisk determines risk level based on storage type and file permissions.
func AssessRisk(storageType StorageType, path string) RiskLevel {
	if storageType == EnvironmentVar {
		return RiskMedium
	}

	if storageType == StorageKeychain || storageType == StorageCredentialManager || storageType == EncryptedDB {
		return RiskMedium
	}

	// Plaintext storage types
	if storageType == PlaintextJSON || storageType == PlaintextYAML ||
		storageType == PlaintextENV || storageType == PlaintextINI {
		if path != "" {
			if _, err := os.Stat(path); err == nil {
				if IsWorldReadable(path) {
					return RiskCritical
				}
				if IsGroupReadable(path) {
					return RiskHigh
				}
			}
		}
		return RiskHigh
	}

	return RiskInfo
}
