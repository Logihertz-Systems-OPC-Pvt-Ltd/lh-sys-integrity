# ==============================================================================
# Product:       lh-sys-integrity (lh-sys)
# Module:        tests.test_verifier
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for filesystem verification and tampering detection."""

from __future__ import annotations

import os
from pathlib import Path

from lh_sys_integrity.baseline import create_baseline
from lh_sys_integrity.models import HashAlgorithm, RuleId, Severity
from lh_sys_integrity.verifier import verify_filesystem


def test_verify_clean_filesystem(tmp_path: Path) -> None:
    """Verify that an untampered directory produces a clean audit report."""
    target_dir = tmp_path / "sys"
    target_dir.mkdir()
    (target_dir / "app.bin").write_bytes(b"Clean binary contents")
    (target_dir / "conf.json").write_text("{}", encoding="utf-8")

    baseline = create_baseline(target_dir, algorithm=HashAlgorithm.SHA256)
    report = verify_filesystem(target_dir, baseline)

    assert report.is_clean
    assert len(report.findings) == 0
    assert report.total_files_checked == 2


def test_verify_content_tampering(tmp_path: Path) -> None:
    """Verify that unauthorized modification of a file's content is detected (FIM001)."""
    target_dir = tmp_path / "sys"
    target_dir.mkdir()
    target_file = target_dir / "target.bin"
    target_file.write_bytes(b"Original untampered bytes")

    baseline = create_baseline(target_dir, algorithm=HashAlgorithm.SHA256)

    # Tamper with the file
    target_file.write_bytes(b"Maliciously altered backdoor bytes")

    report = verify_filesystem(target_dir, baseline)
    assert not report.is_clean

    rule_ids = [f.rule_id for f in report.findings]
    assert RuleId.FIM001_CONTENT_MODIFIED.value in rule_ids
    mod_finding = next(
        f for f in report.findings if f.rule_id == RuleId.FIM001_CONTENT_MODIFIED.value
    )
    assert mod_finding.severity == Severity.CRITICAL
    assert "target.bin" in mod_finding.path


def test_verify_file_injected(tmp_path: Path) -> None:
    """Verify detection of newly injected un-baselined files (FIM002)."""
    target_dir = tmp_path / "sys"
    target_dir.mkdir()
    (target_dir / "valid.txt").write_text("valid", encoding="utf-8")

    baseline = create_baseline(target_dir)

    # Inject an unauthorized binary
    injected_file = target_dir / "backdoor.sh"
    injected_file.write_text("#!/bin/sh\ncat /etc/shadow", encoding="utf-8")
    injected_file.chmod(0o755)

    report = verify_filesystem(target_dir, baseline)
    assert not report.is_clean

    rule_ids = [f.rule_id for f in report.findings]
    assert RuleId.FIM002_FILE_INJECTED.value in rule_ids
    inj_finding = next(f for f in report.findings if f.rule_id == RuleId.FIM002_FILE_INJECTED.value)
    assert inj_finding.path == "backdoor.sh"


def test_verify_file_deleted(tmp_path: Path) -> None:
    """Verify detection of deleted baselined files (FIM003)."""
    target_dir = tmp_path / "sys"
    target_dir.mkdir()
    file_to_delete = target_dir / "critical.conf"
    file_to_delete.write_text("critical security policy", encoding="utf-8")

    baseline = create_baseline(target_dir)

    # Delete critical file
    file_to_delete.unlink()

    report = verify_filesystem(target_dir, baseline)
    assert not report.is_clean

    rule_ids = [f.rule_id for f in report.findings]
    assert RuleId.FIM003_FILE_DELETED.value in rule_ids
    del_finding = next(f for f in report.findings if f.rule_id == RuleId.FIM003_FILE_DELETED.value)
    assert del_finding.severity == Severity.CRITICAL
    assert del_finding.path == "critical.conf"


def test_verify_permission_tampered(tmp_path: Path) -> None:
    """Verify detection of permission alterations, such as world-writable or SUID drift (FIM004)."""
    target_dir = tmp_path / "sys"
    target_dir.mkdir()
    perm_file = target_dir / "service.sh"
    perm_file.write_text("#!/bin/sh\necho service", encoding="utf-8")
    perm_file.chmod(0o644)

    baseline = create_baseline(target_dir)

    # Modify permissions to 0777 (world-writable)
    perm_file.chmod(0o777)

    report = verify_filesystem(target_dir, baseline)
    assert not report.is_clean

    rule_ids = [f.rule_id for f in report.findings]
    assert RuleId.FIM004_PERM_TAMPERED.value in rule_ids
    perm_finding = next(
        f for f in report.findings if f.rule_id == RuleId.FIM004_PERM_TAMPERED.value
    )
    assert perm_finding.severity in (Severity.HIGH, Severity.CRITICAL)


def test_verify_ownership_tampered(tmp_path: Path) -> None:
    """Verify detection of UID/GID ownership drift (FIM005)."""
    target_dir = tmp_path / "sys"
    target_dir.mkdir()
    own_file = target_dir / "root_only.conf"
    own_file.write_text("secret", encoding="utf-8")

    baseline = create_baseline(target_dir)
    # Simulate ownership difference in baseline record
    baseline.files["root_only.conf"].uid = 99999
    baseline.files["root_only.conf"].user = "fake_user"

    report = verify_filesystem(target_dir, baseline)
    assert not report.is_clean

    rule_ids = [f.rule_id for f in report.findings]
    assert RuleId.FIM005_OWNERSHIP_TAMPERED.value in rule_ids


def test_verify_timestomping_detected(tmp_path: Path) -> None:
    """Verify detection of suspicious timestomping backdating (FIM006)."""
    target_dir = tmp_path / "sys"
    target_dir.mkdir()
    ts_file = target_dir / "binary"
    ts_file.write_bytes(b"initial binary")

    baseline = create_baseline(target_dir)
    original_mtime = ts_file.stat().st_mtime

    # Artificially backdate mtime to 1000 seconds before baseline
    backdated_mtime = original_mtime - 1000.0
    os.utime(ts_file, (backdated_mtime, backdated_mtime))

    report = verify_filesystem(target_dir, baseline)
    rule_ids = [f.rule_id for f in report.findings]
    assert RuleId.FIM006_TIMESTOMPING_DETECTED.value in rule_ids


def test_verify_file_type_drift(tmp_path: Path) -> None:
    """Verify detection of type drift when regular file is replaced by symlink (FIM007)."""
    target_dir = tmp_path / "sys"
    target_dir.mkdir()
    reg_file = target_dir / "target.so"
    reg_file.write_bytes(b"regular shared object")

    baseline = create_baseline(target_dir)

    # Replace regular file with symlink pointing elsewhere
    reg_file.unlink()
    secret_file = tmp_path / "secret.so"
    secret_file.write_bytes(b"rogue library")
    reg_file.symlink_to(secret_file)

    report = verify_filesystem(target_dir, baseline)
    rule_ids = [f.rule_id for f in report.findings]
    assert RuleId.FIM007_TYPE_DRIFT.value in rule_ids


def test_verify_manifest_tampering(tmp_path: Path) -> None:
    """Verify detection of baseline manifest checksum mismatch (FIM008)."""
    target_dir = tmp_path / "sys"
    target_dir.mkdir()
    (target_dir / "data.txt").write_text("baseline data", encoding="utf-8")

    baseline = create_baseline(target_dir)
    # Tamper with the recorded manifest checksum
    baseline.metadata.manifest_checksum = (
        "0000000000000000000000000000000000000000000000000000000000000000"
    )

    report = verify_filesystem(target_dir, baseline)
    rule_ids = [f.rule_id for f in report.findings]
    assert RuleId.FIM008_MANIFEST_TAMPERED.value in rule_ids
    assert report.has_critical_or_high
