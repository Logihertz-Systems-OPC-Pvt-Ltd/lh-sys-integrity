# ==============================================================================
# Product:       lh-sys-integrity (lh-sys)
# Module:        src.lh_sys_integrity.hasher
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Cryptographic hashing engine supporting SHA-256, SHA-512, and BLAKE2b."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from lh_sys_integrity.models import HashAlgorithm

CHUNK_SIZE = 65536  # 64 KB read buffer


def get_hashlib_instance(algorithm: HashAlgorithm | str) -> Any:
    """Instantiate the corresponding hashlib object for the given algorithm.

    Args:
        algorithm: Desired HashAlgorithm enum or string identifier.

    Returns:
        A new hashlib hash object.

    Raises:
        ValueError: If the specified algorithm is not supported.
    """
    algo = HashAlgorithm.from_str(algorithm)
    if algo == HashAlgorithm.SHA256:
        return hashlib.sha256()
    if algo == HashAlgorithm.SHA512:
        return hashlib.sha512()
    if algo == HashAlgorithm.BLAKE2B:
        return hashlib.blake2b()
    raise ValueError(f"Unsupported cryptographic hash algorithm: {algorithm}")


def compute_file_hash(
    path: Path,
    algorithm: HashAlgorithm | str = HashAlgorithm.SHA256,
    chunk_size: int = CHUNK_SIZE,
) -> str:
    """Compute the cryptographic hash of a file using streaming I/O.

    Args:
        path: Absolute or relative Path to the file.
        algorithm: Hash algorithm to compute.
        chunk_size: Buffer chunk size in bytes.

    Returns:
        Hexadecimal digest string.

    Raises:
        FileNotFoundError: If the target file does not exist.
        PermissionError: If read permission is denied.
        OSError: On other file system I/O errors.
    """
    hasher = get_hashlib_instance(algorithm)
    with path.open("rb") as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_all_hashes(
    path: Path,
    chunk_size: int = CHUNK_SIZE,
) -> dict[str, str]:
    """Compute SHA-256, SHA-512, and BLAKE2b digests in a single streaming pass.

    Args:
        path: Path to the target file.
        chunk_size: Buffer chunk size in bytes.

    Returns:
        Dictionary mapping algorithm name to its hexadecimal digest.
    """
    h_sha256 = hashlib.sha256()
    h_sha512 = hashlib.sha512()
    h_blake2b = hashlib.blake2b()

    with path.open("rb") as f:
        while chunk := f.read(chunk_size):
            h_sha256.update(chunk)
            h_sha512.update(chunk)
            h_blake2b.update(chunk)

    return {
        HashAlgorithm.SHA256.value: h_sha256.hexdigest(),
        HashAlgorithm.SHA512.value: h_sha512.hexdigest(),
        HashAlgorithm.BLAKE2B.value: h_blake2b.hexdigest(),
    }


def compute_manifest_checksum(files_data: dict[str, Any]) -> str:
    """Generate a canonical SHA-256 checksum across the entire files dictionary.

    Ensures baseline manifests are tamper-evident by producing a deterministic
    hash over sorted, compact JSON representations of the baseline records.

    Args:
        files_data: Dictionary of file records.

    Returns:
        SHA-256 hex digest of the canonical JSON bytes.
    """
    canonical_repr = json.dumps(files_data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical_repr.encode("utf-8")).hexdigest()
