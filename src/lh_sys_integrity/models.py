# ==============================================================================
# Product:       lh-sys-integrity (lh-sys)
# Module:        src.lh_sys_integrity.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Data models and schema definitions for lh-sys-integrity."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class HashAlgorithm(str, Enum):
    """Supported cryptographic hash algorithms."""

    SHA256 = "sha256"
    SHA512 = "sha512"
    BLAKE2B = "blake2b"

    def __str__(self) -> str:
        """Return the lowercase string value of the algorithm."""
        return self.value

    @classmethod
    def from_str(cls, val: str | HashAlgorithm) -> HashAlgorithm:
        """Convert a string or enum to HashAlgorithm."""
        if isinstance(val, cls):
            return val
        s = str(val).lower().strip()
        if "." in s:
            s = s.split(".")[-1]
        try:
            return cls(s)
        except ValueError as err:
            raise ValueError(f"Unsupported cryptographic hash algorithm: {val}") from err


class OutputFormat(str, Enum):
    """Supported report output formats."""

    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"


class Severity(str, Enum):
    # --- Severity Rank & Weighting Structure ---
    # Defines discrete security tiers for findings and threshold gating.
    # Higher ordinal rankings enforce stricter build break / fail-on gates.
    """Finding severity levels conforming to security vulnerability standards."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RuleId(str, Enum):
    """Standardized rule identifiers for FIM and preload security checks."""

    # File Integrity Monitoring (FIM) rules
    FIM001_CONTENT_MODIFIED = "FIM001_CONTENT_MODIFIED"
    FIM002_FILE_INJECTED = "FIM002_FILE_INJECTED"
    FIM003_FILE_DELETED = "FIM003_FILE_DELETED"
    FIM004_PERM_TAMPERED = "FIM004_PERM_TAMPERED"
    FIM005_OWNERSHIP_TAMPERED = "FIM005_OWNERSHIP_TAMPERED"
    FIM006_TIMESTOMPING_DETECTED = "FIM006_TIMESTOMPING_DETECTED"
    FIM007_TYPE_DRIFT = "FIM007_TYPE_DRIFT"
    FIM008_MANIFEST_TAMPERED = "FIM008_MANIFEST_TAMPERED"

    # Preload & Linker Rootkit rules
    PRELOAD001_LD_PRELOAD_ACTIVE = "PRELOAD001_LD_PRELOAD_ACTIVE"
    PRELOAD002_PRELOAD_FILE_WRITABLE = "PRELOAD002_PRELOAD_FILE_WRITABLE"
    PRELOAD003_SUSPICIOUS_LIB_PATH = "PRELOAD003_SUSPICIOUS_LIB_PATH"
    PRELOAD004_MODULE_CONF_WRITABLE = "PRELOAD004_MODULE_CONF_WRITABLE"
    PRELOAD005_SUSPICIOUS_MODULE = "PRELOAD005_SUSPICIOUS_MODULE"
    PRELOAD006_ENV_PRELOAD_SET = "PRELOAD006_ENV_PRELOAD_SET"


@dataclass
class FileRecord:
    """Cryptographic baseline entry for an individual filesystem entity."""

    path: str
    size: int
    mode: int
    mode_octal: str
    permissions: str
    uid: int
    gid: int
    user: str
    group: str
    inode: int
    mtime: float
    mtime_iso: str
    ctime: float
    ctime_iso: str
    algorithm: str
    hash: str
    hashes: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert FileRecord to a JSON-serializable dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FileRecord:
        """Create FileRecord from a dictionary."""
        return cls(
            path=str(data["path"]),
            size=int(data["size"]),
            mode=int(data["mode"]),
            mode_octal=str(data["mode_octal"]),
            permissions=str(data["permissions"]),
            uid=int(data["uid"]),
            gid=int(data["gid"]),
            user=str(data.get("user", "")),
            group=str(data.get("group", "")),
            inode=int(data["inode"]),
            mtime=float(data["mtime"]),
            mtime_iso=str(data["mtime_iso"]),
            ctime=float(data["ctime"]),
            ctime_iso=str(data["ctime_iso"]),
            algorithm=str(data["algorithm"]),
            hash=str(data["hash"]),
            hashes=dict(data.get("hashes", {})),
        )


@dataclass
class ManifestMetadata:
    """Metadata block header for a baseline manifest."""

    generator: str
    version: str
    target_path: str
    algorithm: str
    created_at: str
    file_count: int
    manifest_checksum: str

    def to_dict(self) -> dict[str, Any]:
        """Convert ManifestMetadata to a JSON-serializable dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ManifestMetadata:
        """Create ManifestMetadata from a dictionary."""
        return cls(
            generator=str(data["generator"]),
            version=str(data["version"]),
            target_path=str(data["target_path"]),
            algorithm=str(data["algorithm"]),
            created_at=str(data["created_at"]),
            file_count=int(data["file_count"]),
            manifest_checksum=str(data["manifest_checksum"]),
        )


@dataclass
class BaselineManifest:
    """Complete baseline manifest recording state across target paths."""

    metadata: ManifestMetadata
    files: dict[str, FileRecord]

    def to_dict(self) -> dict[str, Any]:
        """Convert BaselineManifest to a JSON-serializable dictionary."""
        return {
            "metadata": self.metadata.to_dict(),
            "files": {p: rec.to_dict() for p, rec in sorted(self.files.items())},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BaselineManifest:
        """Create BaselineManifest from a dictionary."""
        meta = ManifestMetadata.from_dict(data["metadata"])
        files = {p: FileRecord.from_dict(f) for p, f in data.get("files", {}).items()}
        return cls(metadata=meta, files=files)


@dataclass
class Finding:
    """A detected integrity drift, rootkit hook, or tampering violation."""

    rule_id: str
    severity: Severity
    path: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert Finding to a JSON-serializable dictionary."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "path": self.path,
            "message": self.message,
            "details": self.details,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """Create Finding from a dictionary."""
        return cls(
            rule_id=str(data["rule_id"]),
            severity=Severity(data["severity"]),
            path=str(data["path"]),
            message=str(data["message"]),
            details=dict(data.get("details", {})),
            timestamp=str(data.get("timestamp", "")),
        )


@dataclass
class AuditReport:
    """Consolidated audit report encompassing verification or preload analysis."""

    report_type: str
    target_path: str
    timestamp: str
    duration_seconds: float
    total_files_checked: int
    findings: list[Finding] = field(default_factory=list)

    @property
    def is_clean(self) -> bool:
        """Return True if no integrity violations or rootkit hooks were detected."""
        return len(self.findings) == 0

    @property
    def has_critical_or_high(self) -> bool:
        """Return True if findings contain CRITICAL or HIGH severity issues."""
        return any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings)

    @property
    def critical_count(self) -> int:
        """Number of critical findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Number of high severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        """Number of medium severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        """Number of low severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        """Number of informational findings."""
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    def to_dict(self) -> dict[str, Any]:
        """Convert AuditReport to a JSON-serializable dictionary."""
        return {
            "report_type": self.report_type,
            "target_path": self.target_path,
            "timestamp": self.timestamp,
            "duration_seconds": round(self.duration_seconds, 4),
            "total_files_checked": self.total_files_checked,
            "summary": {
                "is_clean": self.is_clean,
                "total_findings": len(self.findings),
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "findings": [f.to_dict() for f in self.findings],
        }
