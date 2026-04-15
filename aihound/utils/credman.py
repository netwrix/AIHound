"""Windows Credential Manager query utilities."""

from __future__ import annotations

from typing import Optional

from aihound.core.platform import detect_platform, Platform


def query_credential_manager(target: str) -> Optional[str]:
    """Query Windows Credential Manager for a credential by target name.

    Returns the credential value if found, None otherwise.
    Only works on native Windows (not WSL).
    """
    if detect_platform() != Platform.WINDOWS:
        return None

    try:
        import ctypes
        import ctypes.wintypes

        advapi32 = ctypes.windll.advapi32

        class CREDENTIAL(ctypes.Structure):
            _fields_ = [
                ("Flags", ctypes.wintypes.DWORD),
                ("Type", ctypes.wintypes.DWORD),
                ("TargetName", ctypes.wintypes.LPWSTR),
                ("Comment", ctypes.wintypes.LPWSTR),
                ("LastWritten", ctypes.wintypes.FILETIME),
                ("CredentialBlobSize", ctypes.wintypes.DWORD),
                ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
                ("Persist", ctypes.wintypes.DWORD),
                ("AttributeCount", ctypes.wintypes.DWORD),
                ("Attributes", ctypes.c_void_p),
                ("TargetAlias", ctypes.wintypes.LPWSTR),
                ("UserName", ctypes.wintypes.LPWSTR),
            ]

        PCREDENTIAL = ctypes.POINTER(CREDENTIAL)
        CRED_TYPE_GENERIC = 1

        cred_ptr = PCREDENTIAL()

        success = advapi32.CredReadW(
            target,
            CRED_TYPE_GENERIC,
            0,
            ctypes.byref(cred_ptr),
        )

        if success:
            cred = cred_ptr.contents
            blob_size = cred.CredentialBlobSize
            if blob_size > 0:
                blob = ctypes.string_at(cred.CredentialBlob, blob_size)
                advapi32.CredFree(cred_ptr)
                return blob.decode("utf-16-le", errors="replace")
            advapi32.CredFree(cred_ptr)

    except (ImportError, AttributeError, OSError):
        pass

    return None
