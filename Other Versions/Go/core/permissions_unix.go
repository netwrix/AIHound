//go:build !windows

package core

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// GetFileOwner returns the file owner's username. Returns empty string on error.
func GetFileOwner(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	uid := stat.Uid
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return strconv.FormatUint(uint64(uid), 10)
	}
	return u.Username
}
