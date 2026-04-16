package core

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
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

// GetFileMtime returns the file modification time as UTC ISO 8601 string.
// Returns empty string on error.
func GetFileMtime(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return info.ModTime().UTC().Format(time.RFC3339)
}

// GetFileMtimeTime returns the file modification time as time.Time.
// Returns zero time on error; check IsZero() before use.
func GetFileMtimeTime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime().UTC()
}

// DescribeStaleness returns a human-readable staleness string like "3 hours ago" or "45 days ago".
func DescribeStaleness(mtime time.Time) string {
	if mtime.IsZero() {
		return ""
	}
	delta := time.Since(mtime)
	seconds := delta.Seconds()
	if seconds < 60 {
		return "just now"
	}
	if seconds < 3600 {
		mins := int(seconds / 60)
		if mins == 1 {
			return "1 minute ago"
		}
		return fmt.Sprintf("%d minutes ago", mins)
	}
	if seconds < 86400 {
		hours := int(seconds / 3600)
		if hours == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", hours)
	}
	days := int(seconds / 86400)
	if days < 365 {
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	}
	years := days / 365
	if years == 1 {
		return "1 year ago"
	}
	return fmt.Sprintf("%d years ago", years)
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
		storageType == PlaintextENV || storageType == PlaintextINI ||
		storageType == PlaintextFile {
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
