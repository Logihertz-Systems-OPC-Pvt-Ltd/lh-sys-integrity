# ==============================================================================
# Product:       lh-sys-integrity (lh-sys)
# Module:        tests.test_exporters
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for Table, JSON, and SARIF report exporters."""

from __future__ import annotations

import json

from lh_sys_integrity.exporters.json_exporter import export_report_json
from lh_sys_integrity.exporters.sarif_exporter import (
    SARIF_SCHEMA_URI,
    SARIF_VERSION,
    TOOL_NAME,
    export_report_sarif,
    severity_to_sarif_level,
)
from lh_sys_integrity.exporters.table import render_report_table
from lh_sys_integrity.models import AuditReport, Finding, RuleId, Severity


def create_dummy_report(clean: bool = False) -> AuditReport:
    """Helper to generate a test AuditReport."""
    findings = []
    if not clean:
        findings = [
            Finding(
                rule_id=RuleId.FIM001_CONTENT_MODIFIED.value,
                severity=Severity.CRITICAL,
                path="usr/bin/login",
                message="Hash mismatch detected",
                details={"expected": "aaa", "actual": "bbb"},
                timestamp="2026-11-04T00:00:00Z",
            ),
            Finding(
                rule_id=RuleId.FIM004_PERM_TAMPERED.value,
                severity=Severity.HIGH,
                path="etc/sudoers",
                message="World writable permissions detected",
                details={"mode": "0777"},
                timestamp="2026-11-04T00:00:00Z",
            ),
            Finding(
                rule_id=RuleId.FIM005_OWNERSHIP_TAMPERED.value,
                severity=Severity.MEDIUM,
                path="var/log/audit.log",
                message="Ownership changed",
                details={"uid": 1000},
                timestamp="2026-11-04T00:00:00Z",
            ),
        ]

    return AuditReport(
        report_type="verification",
        target_path="/usr",
        timestamp="2026-11-04T00:00:00Z",
        duration_seconds=0.1234,
        total_files_checked=10,
        findings=findings,
    )


def test_table_exporter() -> None:
    """Verify Rich table output contains key headings and finding details."""
    report = create_dummy_report(clean=False)
    rendered = render_report_table(report, console=None)
    assert "lh-fim Security Audit" in rendered
    assert "INTEGRITY VIOLATIONS DETECTED" in rendered
    assert "FIM001_CONTENT_MODIFIED" in rendered
    assert "usr/bin/login" in rendered

    clean_report = create_dummy_report(clean=True)
    clean_rendered = render_report_table(clean_report, console=None)
    assert "INTEGRITY INTACT" in clean_rendered
    assert "No security drift" in clean_rendered


def test_json_exporter() -> None:
    """Verify structured JSON serialization and deserialization."""
    report = create_dummy_report(clean=False)
    json_str = export_report_json(report)
    data = json.loads(json_str)

    assert data["report_type"] == "verification"
    assert data["summary"]["is_clean"] is False
    assert data["summary"]["critical"] == 1
    assert data["summary"]["high"] == 1
    assert len(data["findings"]) == 3
    assert data["findings"][0]["rule_id"] == RuleId.FIM001_CONTENT_MODIFIED.value


def test_sarif_exporter() -> None:
    """Verify OASIS SARIF v2.1.0 output compliance."""
    report = create_dummy_report(clean=False)
    sarif_str = export_report_sarif(report)
    sarif_doc = json.loads(sarif_str)

    assert sarif_doc["$schema"] == SARIF_SCHEMA_URI
    assert sarif_doc["version"] == SARIF_VERSION
    assert len(sarif_doc["runs"]) == 1

    run = sarif_doc["runs"][0]
    assert run["tool"]["driver"]["name"] == TOOL_NAME
    rules = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert RuleId.FIM001_CONTENT_MODIFIED.value in rules
    assert RuleId.FIM004_PERM_TAMPERED.value in rules

    results = run["results"]
    assert len(results) == 3
    assert results[0]["level"] == "error"
    assert (
        results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "usr/bin/login"
    )


def test_severity_to_sarif_level() -> None:
    """Verify correct mapping of internal severity levels to SARIF levels."""
    assert severity_to_sarif_level(Severity.CRITICAL) == "error"
    assert severity_to_sarif_level(Severity.HIGH) == "error"
    assert severity_to_sarif_level(Severity.MEDIUM) == "warning"
    assert severity_to_sarif_level(Severity.LOW) == "note"
    assert severity_to_sarif_level(Severity.INFO) == "note"
