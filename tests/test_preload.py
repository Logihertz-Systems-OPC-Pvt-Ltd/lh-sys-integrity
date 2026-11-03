# ==============================================================================
# Product:       lh-sys-integrity (lh-sys)
# Module:        tests.test_preload
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for Linux dynamic linker, ld.so.preload, and kernel module auditor."""

from __future__ import annotations

from pathlib import Path

import pytest

from lh_sys_integrity.models import RuleId, Severity
from lh_sys_integrity.preload import audit_preload


def test_audit_preload_clean_root(tmp_path: Path) -> None:
    """Verify that a clean root without preload hooks reports clean status."""
    clean_root = tmp_path / "sysroot"
    etc = clean_root / "etc"
    etc.mkdir(parents=True)

    # Standard ld.so.conf with trusted system paths
    ld_conf = etc / "ld.so.conf"
    ld_conf.write_text("/usr/lib\n/lib\n", encoding="utf-8")
    ld_conf.chmod(0o644)

    report = audit_preload(root_path=clean_root)
    assert report.is_clean
    assert len(report.findings) == 0


def test_audit_preload_active_hook(tmp_path: Path) -> None:
    """Verify detection of active shared object hooks in ld.so.preload (PRELOAD001)."""
    fake_root = tmp_path / "sysroot"
    etc = fake_root / "etc"
    etc.mkdir(parents=True)

    preload_file = etc / "ld.so.preload"
    preload_file.write_text("/lib/x86_64-linux-gnu/librootkit.so\n", encoding="utf-8")

    report = audit_preload(root_path=fake_root)
    assert not report.is_clean

    rule_ids = [f.rule_id for f in report.findings]
    assert RuleId.PRELOAD001_LD_PRELOAD_ACTIVE.value in rule_ids
    f = next(
        item
        for item in report.findings
        if item.rule_id == RuleId.PRELOAD001_LD_PRELOAD_ACTIVE.value
    )
    assert f.severity in (Severity.CRITICAL, Severity.HIGH)
    assert "librootkit.so" in f.message


def test_audit_preload_suspicious_lib_dir(tmp_path: Path) -> None:
    """Verify detection of suspicious directories in ld.so.conf (PRELOAD003)."""
    fake_root = tmp_path / "sysroot"
    etc = fake_root / "etc"
    etc.mkdir(parents=True)

    ld_conf = etc / "ld.so.conf"
    # Pointing to /tmp or relative path
    ld_conf.write_text("/tmp/malicious_libs\n./relative_path\n", encoding="utf-8")

    report = audit_preload(root_path=fake_root)
    assert not report.is_clean

    rule_ids = [f.rule_id for f in report.findings]
    assert RuleId.PRELOAD003_SUSPICIOUS_LIB_PATH.value in rule_ids


def test_audit_preload_recursive_include(tmp_path: Path) -> None:
    """Verify recursive include traversal in ld.so.conf.d/."""
    fake_root = tmp_path / "sysroot"
    etc = fake_root / "etc"
    etc.mkdir(parents=True)

    ld_conf = etc / "ld.so.conf"
    ld_conf.write_text("include /etc/ld.so.conf.d/*.conf\n", encoding="utf-8")

    conf_d = etc / "ld.so.conf.d"
    conf_d.mkdir()
    (conf_d / "custom.conf").write_text("/dev/shm/hidden_libs\n", encoding="utf-8")

    report = audit_preload(root_path=fake_root)
    assert not report.is_clean

    rule_ids = [f.rule_id for f in report.findings]
    assert RuleId.PRELOAD003_SUSPICIOUS_LIB_PATH.value in rule_ids


def test_audit_preload_suspicious_kernel_module(tmp_path: Path) -> None:
    """Verify detection of rootkit kernel module in /etc/modules (PRELOAD005)."""
    fake_root = tmp_path / "sysroot"
    etc = fake_root / "etc"
    etc.mkdir(parents=True)

    modules_file = etc / "modules"
    modules_file.write_text("loop\ndiamorphine\noverlay\n", encoding="utf-8")

    report = audit_preload(root_path=fake_root)
    assert not report.is_clean

    rule_ids = [f.rule_id for f in report.findings]
    assert RuleId.PRELOAD005_SUSPICIOUS_MODULE.value in rule_ids
    mod_finding = next(
        f for f in report.findings if f.rule_id == RuleId.PRELOAD005_SUSPICIOUS_MODULE.value
    )
    assert mod_finding.severity == Severity.CRITICAL
    assert "diamorphine" in mod_finding.message


def test_audit_preload_env_variables(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify detection of LD_PRELOAD in environment variables (PRELOAD006)."""
    fake_root = tmp_path / "sysroot"
    fake_root.mkdir()

    monkeypatch.setenv("LD_PRELOAD", "/tmp/injector.so")
    report = audit_preload(root_path=fake_root)

    assert not report.is_clean
    rule_ids = [f.rule_id for f in report.findings]
    assert RuleId.PRELOAD006_ENV_PRELOAD_SET.value in rule_ids
