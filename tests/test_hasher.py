# ==============================================================================
# Product:       lh-sys-integrity (lh-sys)
# Module:        tests.test_hasher
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for cryptographic hasher module."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from lh_sys_integrity.hasher import (
    compute_all_hashes,
    compute_file_hash,
    compute_manifest_checksum,
    get_hashlib_instance,
)
from lh_sys_integrity.models import HashAlgorithm


def test_get_hashlib_instance() -> None:
    """Verify hash instance instantiations for supported algorithms."""
    assert get_hashlib_instance(HashAlgorithm.SHA256).name == "sha256"
    assert get_hashlib_instance(HashAlgorithm.SHA512).name == "sha512"
    assert get_hashlib_instance(HashAlgorithm.BLAKE2B).name == "blake2b"
    assert get_hashlib_instance("sha256").name == "sha256"

    with pytest.raises(ValueError, match="Unsupported cryptographic hash algorithm"):
        get_hashlib_instance("md5")


def test_compute_file_hash(tmp_path: Path) -> None:
    """Verify streaming hash calculation matches expected digests."""
    test_file = tmp_path / "test.bin"
    payload = b"Logihertz Systems File Integrity Monitoring Payload\n" * 1000
    test_file.write_bytes(payload)

    expected_sha256 = hashlib.sha256(payload).hexdigest()
    expected_sha512 = hashlib.sha512(payload).hexdigest()
    expected_blake2b = hashlib.blake2b(payload).hexdigest()

    assert compute_file_hash(test_file, HashAlgorithm.SHA256) == expected_sha256
    assert compute_file_hash(test_file, HashAlgorithm.SHA512) == expected_sha512
    assert compute_file_hash(test_file, HashAlgorithm.BLAKE2B) == expected_blake2b


def test_compute_all_hashes(tmp_path: Path) -> None:
    """Verify single-pass computation of all supported digests."""
    test_file = tmp_path / "data.txt"
    content = b"Kernel integrity baseline test vector"
    test_file.write_bytes(content)

    digests = compute_all_hashes(test_file)
    assert digests[HashAlgorithm.SHA256.value] == hashlib.sha256(content).hexdigest()
    assert digests[HashAlgorithm.SHA512.value] == hashlib.sha512(content).hexdigest()
    assert digests[HashAlgorithm.BLAKE2B.value] == hashlib.blake2b(content).hexdigest()


def test_compute_manifest_checksum() -> None:
    """Verify deterministic manifest checksumming and sensitivity to changes."""
    files_a = {
        "bin/login": {"size": 1024, "hash": "abc"},
        "etc/passwd": {"size": 2048, "hash": "def"},
    }
    files_b = {
        "etc/passwd": {"size": 2048, "hash": "def"},
        "bin/login": {"size": 1024, "hash": "abc"},
    }
    # Key order in dict should not alter canonical checksum
    assert compute_manifest_checksum(files_a) == compute_manifest_checksum(files_b)

    # Content change alters checksum
    files_c = {
        "bin/login": {"size": 1025, "hash": "abc"},
        "etc/passwd": {"size": 2048, "hash": "def"},
    }
    assert compute_manifest_checksum(files_a) != compute_manifest_checksum(files_c)
