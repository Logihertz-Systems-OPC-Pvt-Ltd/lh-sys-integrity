# ==============================================================================
# Product:       lh-sys-integrity (lh-sys)
# Module:        tests.test_cli
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit and integration tests for lh-fim CLI commands."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lh_sys_integrity.cli import app

runner = CliRunner()


def test_cli_help() -> None:
    """Verify top-level help displays all available subcommands."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "init" in result.stdout
    assert "verify" in result.stdout
    assert "audit-preload" in result.stdout


def test_cli_init_command(tmp_path: Path) -> None:
    """Verify init subcommand generates a baseline file."""
    target_dir = tmp_path / "sys"
    target_dir.mkdir()
    (target_dir / "app.sh").write_text("#!/bin/sh\necho test", encoding="utf-8")
    (target_dir / "cache.tmp").write_text("temp", encoding="utf-8")

    baseline_out = tmp_path / "baseline.json"
    result = runner.invoke(
        app,
        [
            "init",
            str(target_dir),
            "--algorithm",
            "blake2b",
            "--exclude",
            "*.tmp",
            "--output",
            str(baseline_out),
        ],
    )
    assert result.exit_code == 0
    assert "Baseline generated successfully" in result.stdout
    assert baseline_out.exists()

    data = json.loads(baseline_out.read_text(encoding="utf-8"))
    assert data["metadata"]["algorithm"] == "blake2b"
    assert "app.sh" in data["files"]
    assert "cache.tmp" not in data["files"]


def test_cli_verify_clean(tmp_path: Path) -> None:
    """Verify verify command returns exit code 0 when no drift is detected."""
    target_dir = tmp_path / "sys"
    target_dir.mkdir()
    (target_dir / "daemon").write_bytes(b"daemon binary bytes")

    baseline_out = tmp_path / "baseline.json"
    init_res = runner.invoke(app, ["init", str(target_dir), "--output", str(baseline_out)])
    assert init_res.exit_code == 0

    verify_res = runner.invoke(
        app,
        ["verify", str(target_dir), "--baseline", str(baseline_out)],
    )
    assert verify_res.exit_code == 0
    assert "INTEGRITY INTACT" in verify_res.stdout


def test_cli_verify_tampered_json_and_sarif(tmp_path: Path) -> None:
    """Verify verify command detects tampering, exits with code 1, and formats JSON/SARIF."""
    target_dir = tmp_path / "sys"
    target_dir.mkdir()
    target_file = target_dir / "login"
    target_file.write_bytes(b"original login")

    baseline_out = tmp_path / "baseline.json"
    runner.invoke(app, ["init", str(target_dir), "--output", str(baseline_out)])

    # Tamper with target file
    target_file.write_bytes(b"tampered backdoor login")

    # 1. Test table format (default) returns code 1
    table_res = runner.invoke(app, ["verify", str(target_dir), "--baseline", str(baseline_out)])
    assert table_res.exit_code == 1
    assert "INTEGRITY VIOLATIONS DETECTED" in table_res.stdout

    # 2. Test JSON output format to file
    json_out_file = tmp_path / "report.json"
    json_res = runner.invoke(
        app,
        [
            "verify",
            str(target_dir),
            "--baseline",
            str(baseline_out),
            "--format",
            "json",
            "--output",
            str(json_out_file),
        ],
    )
    assert json_res.exit_code == 1
    assert json_out_file.exists()
    json_data = json.loads(json_out_file.read_text(encoding="utf-8"))
    assert json_data["summary"]["is_clean"] is False
    assert json_data["findings"][0]["rule_id"] == "FIM001_CONTENT_MODIFIED"

    # 3. Test SARIF format
    sarif_res = runner.invoke(
        app,
        [
            "verify",
            str(target_dir),
            "--baseline",
            str(baseline_out),
            "--format",
            "sarif",
        ],
    )
    assert sarif_res.exit_code == 1
    sarif_data = json.loads(sarif_res.stdout)
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"][0]["results"]) >= 1


def test_cli_audit_preload(tmp_path: Path) -> None:
    """Verify audit-preload subcommand against clean and hooked roots."""
    sysroot = tmp_path / "sysroot"
    etc = sysroot / "etc"
    etc.mkdir(parents=True)

    # 1. Clean audit
    clean_res = runner.invoke(app, ["audit-preload", "--root", str(sysroot)])
    assert clean_res.exit_code == 0
    assert "INTEGRITY INTACT" in clean_res.stdout

    # 2. Introduce preload hook
    (etc / "ld.so.preload").write_text("/lib/evil.so\n", encoding="utf-8")
    hook_res = runner.invoke(
        app,
        ["audit-preload", "--root", str(sysroot), "--format", "table"],
    )
    assert hook_res.exit_code == 1
    assert "PRELOAD001_LD_PRELOAD_ACTIVE" in hook_res.stdout

    # 3. Output to SARIF file
    sarif_file = tmp_path / "preload.sarif"
    sarif_res = runner.invoke(
        app,
        [
            "audit-preload",
            "--root",
            str(sysroot),
            "--format",
            "sarif",
            "--output",
            str(sarif_file),
        ],
    )
    assert sarif_res.exit_code == 1
    assert sarif_file.exists()


def test_cli_error_handling(tmp_path: Path) -> None:
    """Verify error exit codes and messages on bad inputs."""
    missing_dir = tmp_path / "does_not_exist"
    res_init = runner.invoke(app, ["init", str(missing_dir)])
    assert res_init.exit_code != 0

    bad_baseline = tmp_path / "bad.json"
    bad_baseline.write_text("{bad json", encoding="utf-8")
    valid_dir = tmp_path / "valid"
    valid_dir.mkdir()
    res_verify = runner.invoke(app, ["verify", str(valid_dir), "--baseline", str(bad_baseline)])
    assert res_verify.exit_code == 2


def test_cli_stdout_formats_and_table_output(tmp_path: Path) -> None:
    """Verify table writing to file and stdout streaming of formats."""
    sys_dir = tmp_path / "sys"
    sys_dir.mkdir()
    (sys_dir / "file.txt").write_text("hello", encoding="utf-8")
    baseline_path = tmp_path / "base.json"
    runner.invoke(app, ["init", str(sys_dir), "--output", str(baseline_path)])

    # Table output to file
    table_file = tmp_path / "table.txt"
    res_table = runner.invoke(
        app,
        ["verify", str(sys_dir), "--baseline", str(baseline_path), "--output", str(table_file)],
    )
    assert res_table.exit_code == 0
    assert table_file.exists()

    # JSON output to stdout
    res_json = runner.invoke(
        app,
        ["verify", str(sys_dir), "--baseline", str(baseline_path), "--format", "json"],
    )
    assert res_json.exit_code == 0
    parsed = json.loads(res_json.stdout)
    assert parsed["summary"]["is_clean"] is True

    # Audit preload json to stdout
    clean_root = tmp_path / "empty_root"
    clean_root.mkdir()
    res_preload_json = runner.invoke(
        app, ["audit-preload", "--root", str(clean_root), "--format", "json"]
    )
    assert res_preload_json.exit_code == 0
    parsed_preload = json.loads(res_preload_json.stdout)
    assert parsed_preload["report_type"] == "preload_audit"

    # Audit preload table to file
    preload_tbl = tmp_path / "preload_table.txt"
    res_preload_tbl = runner.invoke(
        app,
        [
            "audit-preload",
            "--root",
            str(clean_root),
            "--format",
            "table",
            "--output",
            str(preload_tbl),
        ],
    )
    assert res_preload_tbl.exit_code == 0
    assert preload_tbl.exists()


def test_cli_main_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify main() entry point executes correctly."""
    from lh_sys_integrity.cli import main

    monkeypatch.setattr("sys.argv", ["lh-fim", "--help"])
    try:
        main()
    except SystemExit as err:
        assert err.code == 0
