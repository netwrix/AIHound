//go:build windows

package utils

import (
	"fmt"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

var (
	advapi32    = syscall.NewLazyDLL("advapi32.dll")
	procCredRead = advapi32.NewProc("CredReadW")
	procCredFree = advapi32.NewProc("CredFree")
)

const credTypeGeneric = 1

// credential mirrors the Windows CREDENTIAL structure.
type credential struct {
	Flags              uint32
	Type               uint32
	TargetName         *uint16
	Comment            *uint16
	LastWritten        syscall.Filetime
	CredentialBlobSize uint32
	CredentialBlob     *byte
	Persist            uint32
	AttributeCount     uint32
	Attributes         uintptr
	TargetAlias        *uint16
	UserName           *uint16
}

// QueryCredentialManager queries the Windows Credential Manager for a
// credential by target name. Returns the credential value if found.
func QueryCredentialManager(target string) (string, error) {
	targetPtr, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return "", fmt.Errorf("invalid target name: %w", err)
	}

	var credPtr *credential
	ret, _, callErr := procCredRead.Call(
		uintptr(unsafe.Pointer(targetPtr)),
		uintptr(credTypeGeneric),
		0,
		uintptr(unsafe.Pointer(&credPtr)),
	)
	if ret == 0 {
		return "", fmt.Errorf("CredReadW failed: %w", callErr)
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(credPtr)))

	if credPtr.CredentialBlobSize == 0 {
		return "", nil
	}

	// Read the credential blob bytes.
	blobBytes := unsafe.Slice(credPtr.CredentialBlob, credPtr.CredentialBlobSize)

	// Decode as UTF-16LE.
	if len(blobBytes)%2 != 0 {
		// Odd number of bytes; append a zero byte for safe decoding.
		blobBytes = append(blobBytes, 0)
	}
	u16 := make([]uint16, len(blobBytes)/2)
	for i := range u16 {
		u16[i] = uint16(blobBytes[2*i]) | uint16(blobBytes[2*i+1])<<8
	}
	return string(utf16.Decode(u16)), nil
}
