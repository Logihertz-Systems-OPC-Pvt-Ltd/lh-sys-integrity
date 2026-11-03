# ==============================================================================
# Product:       lh-sys-integrity (lh-sys)
# Module:        tests.test_baseline
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for baseline manifest creation and persistence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from lh_sys_integrity.baseline import (
    create_baseline,
    format_mode_octal,
    is_excluded,
    load_baseline,
    save_baseline,
    verify_baseline_checksum,
)
from lh_sys_integrity.models import HashAlgorithm


def test_format_mode_octal() -> None:
    """Verify mode formatting returns 4-digit octal string."""
    assert format_mode_octal(0o755) == "0755"
    assert format_mode_octal(0o644) == "0644"
    assert format_mode_octal(0o4755) == "4755"


def test_is_excluded() -> None:
    """Verify exclusion pattern matching logic."""
    assert is_excluded("tmp/scratch.log", ["*.log"])
    assert is_excluded("backup/cache/data.bin", ["*/cache/*"])
    assert not is_excluded("usr/bin/login", ["*.tmp", "*.log"])
    assert is_excluded("temp.swp", ["*.swp"])


def test_create_and_save_baseline(tmp_path: Path) -> None:
    """Verify recursive directory baseline creation and saving."""
    target_dir = tmp_path / "sysroot"
    target_dir.mkdir()

    bin_dir = target_dir / "bin"
    bin_dir.mkdir()
    (bin_dir / "bash").write_text("#!/bin/sh\necho bash", encoding="utf-8")
    (bin_dir / "sh").write_text("#!/bin/sh\necho sh", encoding="utf-8")

    etc_dir = target_dir / "etc"
    etc_dir.mkdir()
    (etc_dir / "hosts").write_text("127.0.0.1 localhost\n", encoding="utf-8")
    (etc_dir / "ignored.tmp").write_text("temporary scratch", encoding="utf-8")

    manifest = create_baseline(
        target_path=target_dir,
        algorithm=HashAlgorithm.SHA256,
        excludes=["*.tmp"],
    )

    assert manifest.metadata.file_count == 3
    assert "bin/bash" in manifest.files
    assert "bin/sh" in manifest.files
    assert "etc/hosts" in manifest.files
    assert "etc/ignored.tmp" not in manifest.files
    assert manifest.metadata.algorithm == "sha256"
    assert verify_baseline_checksum(manifest)

    # Save and reload
    output_json = tmp_path / "baseline.json"
    save_baseline(manifest, output_json)
    assert output_json.exists()

    loaded = load_baseline(output_json)
    assert loaded.metadata.file_count == 3
    assert loaded.files["bin/bash"].hash == manifest.files["bin/bash"].hash
    assert verify_baseline_checksum(loaded)


def test_create_baseline_single_file(tmp_path: Path) -> None:
    """Verify baseline generation targeting a single file."""
    single_file = tmp_path / "config.ini"
    single_file.write_text("[section]\nkey=val\n", encoding="utf-8")

    manifest = create_baseline(target_path=single_file, algorithm=HashAlgorithm.BLAKE2B)
    assert manifest.metadata.file_count == 1
    assert "config.ini" in manifest.files
    assert manifest.files["config.ini"].algorithm == "blake2b"


def test_load_baseline_corrupt_or_missing(tmp_path: Path) -> None:
    """Verify proper exceptions on missing or malformed baseline files."""
    missing = tmp_path / "nonexistent.json"
    with pytest.raises(FileNotFoundError):
        load_baseline(missing)

    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{invalid json", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid baseline JSON format"):
        load_baseline(bad_json)

    missing_sections = tmp_path / "incomplete.json"
    missing_sections.write_text(json.dumps({"some_key": 1}), encoding="utf-8")
    with pytest.raises(ValueError, match="Malformed baseline manifest"):
        load_baseline(missing_sections)
