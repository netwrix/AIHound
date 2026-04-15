"""Base scanner interface and data models."""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
import datetime

logger = logging.getLogger("aihound.scanner")


class StorageType(Enum):
    PLAINTEXT_JSON = "plaintext_json"
    PLAINTEXT_YAML = "plaintext_yaml"
    PLAINTEXT_ENV = "plaintext_env"
    PLAINTEXT_INI = "plaintext_ini"
    KEYCHAIN = "keychain"
    CREDENTIAL_MANAGER = "credman"
    ENCRYPTED_DB = "encrypted_db"
    ENVIRONMENT_VAR = "env_var"
    UNKNOWN = "unknown"


class RiskLevel(Enum):
    CRITICAL = "critical"   # Plaintext + world-readable
    HIGH = "high"           # Plaintext + user-readable only
    MEDIUM = "medium"       # OS credential store (extractable with user access)
    LOW = "low"             # Encrypted or not present
    INFO = "info"           # Metadata only, no credential value


@dataclass
class CredentialFinding:
    tool_name: str
    credential_type: str
    storage_type: StorageType
    location: str
    exists: bool
    risk_level: RiskLevel
    value_preview: Optional[str] = None
    raw_value: Optional[str] = None
    file_permissions: Optional[str] = None
    file_owner: Optional[str] = None
    expiry: Optional[datetime.datetime] = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {
            "tool_name": self.tool_name,
            "credential_type": self.credential_type,
            "storage_type": self.storage_type.value,
            "location": self.location,
            "exists": self.exists,
            "risk_level": self.risk_level.value,
            "value_preview": self.value_preview,
            "file_permissions": self.file_permissions,
            "file_owner": self.file_owner,
            "expiry": self.expiry.isoformat() if self.expiry else None,
            "notes": self.notes,
        }
        # Never include raw_value in serialized output
        return d


@dataclass
class ScanResult:
    scanner_name: str
    platform: str
    findings: list[CredentialFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    scan_time: float = 0.0

    def to_dict(self) -> dict:
        return {
            "scanner_name": self.scanner_name,
            "platform": self.platform,
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
            "scan_time": self.scan_time,
        }


class BaseScanner(ABC):
    """Abstract base class for all credential scanners."""

    @abstractmethod
    def name(self) -> str:
        """Human-readable name for this scanner."""
        ...

    @abstractmethod
    def slug(self) -> str:
        """CLI-friendly identifier (e.g., 'claude-code')."""
        ...

    @abstractmethod
    def scan(self, show_secrets: bool = False) -> ScanResult:
        """Run the scan and return results."""
        ...

    def is_applicable(self) -> bool:
        """Return False if this scanner doesn't apply to the current platform."""
        return True

    def run(self, show_secrets: bool = False) -> ScanResult:
        """Run scan with timing. Catches exceptions to prevent one scanner from killing the whole run."""
        start = time.time()
        try:
            result = self.scan(show_secrets=show_secrets)
        except Exception as e:
            logger.error("Scanner '%s' failed: %s", self.name(), e, exc_info=True)
            result = ScanResult(
                scanner_name=self.name(),
                platform="",
                errors=[f"Scanner failed: {e}"],
            )
        result.scan_time = time.time() - start
        logger.debug("Scanner '%s' completed in %.2fs (%d findings)",
                      self.name(), result.scan_time, len(result.findings))
        return result
