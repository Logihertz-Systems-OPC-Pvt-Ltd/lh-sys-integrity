# ==============================================================================
# Product:       lh-sys-integrity (lh-sys)
# Module:        src.lh_sys_integrity.baseline
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Baseline manifest generation and persistence for file integrity monitoring."""

from __future__ import annotations

import fnmatch
import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

from lh_sys_integrity.hasher import (
    compute_all_hashes,
    compute_manifest_checksum,
)
from lh_sys_integrity.models import (
    BaselineManifest,
    FileRecord,
    HashAlgorithm,
    ManifestMetadata,
)

GENERATOR_ID = "lh-fim v0.1.0 (Logihertz Systems OPC Pvt Ltd)"
MANIFEST_VERSION = "1.0.0"


def format_mode_octal(mode: int) -> str:
    """Format file mode bits as a 4-digit octal string (e.g., '0755', '4755')."""
    return f"{stat.S_IMODE(mode):04o}"


def get_user_name(uid: int) -> str:
    """Resolve numeric UID to username, falling back to string UID on failure."""
    try:
        import pwd

        return pwd.getpwuid(uid).pw_name
    except (KeyError, ImportError, OverflowError):
        return str(uid)


def get_group_name(gid: int) -> str:
    """Resolve numeric GID to groupname, falling back to string GID on failure."""
    try:
        import grp

        return grp.getgrgid(gid).gr_name
    except (KeyError, ImportError, OverflowError):
        return str(gid)


def is_excluded(relative_path: str, excludes: list[str] | None) -> bool:
    """Check if relative path matches any exclusion glob patterns.

    Args:
        relative_path: POSIX relative path to check.
        excludes: List of glob patterns.

    Returns:
        True if matched by any pattern; False otherwise.
    """
    if not excludes:
        return False

    name = Path(relative_path).name
    for pattern in excludes:
        # Match against full relative path or base filename
        if fnmatch.fnmatch(relative_path, pattern) or fnmatch.fnmatch(name, pattern):
            return True
        # Match directories within pattern (e.g. "*/cache/*")
        if pattern.endswith("/") and fnmatch.fnmatch(relative_path + "/", pattern):
            return True
    return False


def create_baseline(
    target_path: Path,
    algorithm: HashAlgorithm | str = HashAlgorithm.SHA256,
    excludes: list[str] | None = None,
) -> BaselineManifest:
    """Scan the target directory or file and generate a cryptographic BaselineManifest.

    Args:
        target_path: Directory or file to baseline.
        algorithm: HashAlgorithm to record as primary.
        excludes: List of glob exclusion patterns.

    Returns:
        BaselineManifest containing metadata and deterministic file records.

    Raises:
        FileNotFoundError: If the target_path does not exist.
        NotADirectoryError: If target_path is not a valid directory or file.
    """
    resolved_target = target_path.resolve()
    if not resolved_target.exists():
        raise FileNotFoundError(f"Target path does not exist: {target_path}")

    algo_enum = HashAlgorithm.from_str(algorithm)
    files_map: dict[str, FileRecord] = {}

    if resolved_target.is_file():
        candidates = [resolved_target]
        base_dir = resolved_target.parent
    else:
        candidates = []
        for root, dirs, files in os.walk(resolved_target, followlinks=False):
            # Sort for deterministic traversal
            dirs.sort()
            files.sort()
            for filename in files:
                candidates.append(Path(root) / filename)
        base_dir = resolved_target

    for file_path in candidates:
        rel_path = file_path.relative_to(base_dir).as_posix()
        if is_excluded(rel_path, excludes):
            continue

        try:
            st = file_path.lstat()
            # If it is a symlink, record link target info without traversing
            is_symlink = stat.S_ISLNK(st.st_mode)
            if is_symlink:
                link_target = os.readlink(file_path)
                # For symlinks, hash the link target string deterministically
                primary_hash = compute_manifest_checksum({"symlink_target": link_target})
                hashes = {
                    HashAlgorithm.SHA256.value: primary_hash,
                    HashAlgorithm.SHA512.value: primary_hash,
                    HashAlgorithm.BLAKE2B.value: primary_hash,
                }
            else:
                hashes = compute_all_hashes(file_path)
                primary_hash = hashes[algo_enum.value]

            mtime_dt = datetime.fromtimestamp(st.st_mtime, tz=UTC)
            ctime_dt = datetime.fromtimestamp(st.st_ctime, tz=UTC)

            record = FileRecord(
                path=rel_path,
                size=st.st_size,
                mode=st.st_mode,
                mode_octal=format_mode_octal(st.st_mode),
                permissions=stat.filemode(st.st_mode),
                uid=st.st_uid,
                gid=st.st_gid,
                user=get_user_name(st.st_uid),
                group=get_group_name(st.st_gid),
                inode=st.st_ino,
                mtime=st.st_mtime,
                mtime_iso=mtime_dt.isoformat(),
                ctime=st.st_ctime,
                ctime_iso=ctime_dt.isoformat(),
                algorithm=algo_enum.value,
                hash=primary_hash,
                hashes=hashes,
            )
            files_map[rel_path] = record
        except (PermissionError, FileNotFoundError, OSError):
            # In live environments, skip unreadable ephemeral files or record minimal
            continue

    # Generate tamper-evident manifest checksum over sorted file records
    serialized_files = {p: rec.to_dict() for p, rec in sorted(files_map.items())}
    manifest_checksum = compute_manifest_checksum(serialized_files)

    created_at = datetime.now(UTC).isoformat()
    metadata = ManifestMetadata(
        generator=GENERATOR_ID,
        version=MANIFEST_VERSION,
        target_path=str(resolved_target),
        algorithm=algo_enum.value,
        created_at=created_at,
        file_count=len(files_map),
        manifest_checksum=manifest_checksum,
    )

    return BaselineManifest(metadata=metadata, files=files_map)


def save_baseline(manifest: BaselineManifest, output_path: Path) -> None:
    """Save BaselineManifest to JSON file with deterministic formatting.

    Args:
        manifest: BaselineManifest instance.
        output_path: Path where JSON manifest should be written.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(manifest.to_dict(), f, indent=2, sort_keys=True)


def load_baseline(baseline_path: Path) -> BaselineManifest:
    """Load BaselineManifest from a JSON file.

    Args:
        baseline_path: Path to the JSON manifest.

    Returns:
        Loaded BaselineManifest.

    Raises:
        FileNotFoundError: If the manifest file does not exist.
        ValueError: If the file is not valid manifest JSON.
    """
    if not baseline_path.exists():
        raise FileNotFoundError(f"Baseline file does not exist: {baseline_path}")

    with baseline_path.open("r", encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as err:
            raise ValueError(f"Invalid baseline JSON format: {err}") from err

    if "metadata" not in data or "files" not in data:
        raise ValueError("Malformed baseline manifest: missing 'metadata' or 'files' section")

    return BaselineManifest.from_dict(data)


def verify_baseline_checksum(manifest: BaselineManifest) -> bool:
    """Verify that the manifest's internal cryptographic checksum matches its contents.

    Args:
        manifest: BaselineManifest to check.

    Returns:
        True if the checksum is valid; False if the manifest was tampered with.
    """
    serialized_files = {p: rec.to_dict() for p, rec in sorted(manifest.files.items())}
    expected_checksum = compute_manifest_checksum(serialized_files)
    return expected_checksum == manifest.metadata.manifest_checksum
