# ==============================================================================
# Product:       lh-sys-integrity (lh-sys)
# Module:        src.lh_sys_integrity.preload
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Linux dynamic linker, ld.so.preload, and kernel module rootkit auditor."""

from __future__ import annotations

import glob
import os
import stat
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from lh_sys_integrity.models import (
    AuditReport,
    Finding,
    RuleId,
    Severity,
)

# Known malicious Linux kernel module rootkit signatures
KNOWN_ROOTKIT_MODULES = {
    "diamorphine",
    "reptile",
    "suterusu",
    "vlany",
    "adore-ng",
    "knark",
    "synapsys",
    "mood-nt",
    "kis",
    "kbeast",
    "rooty",
    "enyelkm",
    "heroin",
    "override",
    "rkload",
}

# Directories that should NEVER appear in dynamic linker search paths
SUSPICIOUS_DIR_PREFIXES = (
    "/tmp",  # nosec B108
    "/var/tmp",  # nosec B108
    "/dev/shm",  # nosec B108
    "/home",
    "/root",
    "/run/user",
    "/mnt",
    "/media",
)


def is_writable_by_others(mode: int) -> bool:
    """Check if mode bits allow world or group write permissions without sticky bit."""
    return bool(mode & stat.S_IWOTH)


def is_non_root_writable(st: os.stat_result, is_real_root: bool = True) -> bool:
    """Check if file is writable by non-root users."""
    if bool(st.st_mode & stat.S_IWOTH):
        return True
    if bool(st.st_mode & stat.S_IWGRP) and st.st_gid != 0:
        return True
    if is_real_root:
        return bool(st.st_uid != 0 and (st.st_mode & stat.S_IWUSR))
    return False


def parse_ld_so_conf(
    conf_path: Path,
    root_path: Path,
    visited: set[Path] | None = None,
) -> tuple[list[str], list[Path]]:
    """Parse ld.so.conf and recursively process include directives.

    Args:
        conf_path: Path to the conf file.
        root_path: Sysroot directory.
        visited: Set of already parsed configuration paths to prevent cycles.

    Returns:
        Tuple of (discovered library directory paths, list of parsed conf files).
    """
    if visited is None:
        visited = set()

    canonical = conf_path.resolve()
    if canonical in visited or not conf_path.is_file():
        return [], []

    visited.add(canonical)
    lib_paths: list[str] = []
    conf_files: list[Path] = [conf_path]

    try:
        lines = conf_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return [], conf_files

    for line in lines:
        cleaned = line.split("#", 1)[0].strip()
        if not cleaned:
            continue

        if cleaned.startswith("include "):
            include_pattern = cleaned.split(" ", 1)[1].strip()
            # If pattern is absolute, resolve against root_path
            if include_pattern.startswith("/"):
                search_pattern = str(root_path / include_pattern.lstrip("/"))
            else:
                search_pattern = str(conf_path.parent / include_pattern)

            for matched in sorted(glob.glob(search_pattern)):
                matched_p = Path(matched)
                if matched_p.is_file():
                    sub_paths, sub_files = parse_ld_so_conf(matched_p, root_path, visited)
                    lib_paths.extend(sub_paths)
                    conf_files.extend(sub_files)
        else:
            lib_paths.append(cleaned)

    return lib_paths, conf_files


def audit_preload(root_path: Path = Path("/")) -> AuditReport:
    """Audit dynamic linker, preload, and kernel module configurations for rootkits.

    Args:
        root_path: System root directory to audit (default: '/').

    Returns:
        AuditReport with findings detailing rootkit hooks or insecure linker configs.
    """
    start_time = time.perf_counter()
    report_timestamp = datetime.now(UTC).isoformat()
    findings: list[Finding] = []
    files_checked = 0

    resolved_root = root_path.resolve()
    is_real_root = resolved_root == Path("/").resolve()

    # 1. Audit /etc/ld.so.preload
    preload_file = resolved_root / "etc/ld.so.preload"
    if preload_file.exists():
        files_checked += 1
        try:
            st = preload_file.lstat()
            # Permission check on /etc/ld.so.preload
            if is_non_root_writable(st, is_real_root=is_real_root):
                findings.append(
                    Finding(
                        rule_id=RuleId.PRELOAD002_PRELOAD_FILE_WRITABLE.value,
                        severity=Severity.CRITICAL,
                        path=str(preload_file),
                        message=(
                            f"ld.so.preload configuration file is writable by non-root users: "
                            f"{oct(st.st_mode)}"
                        ),
                        details={
                            "mode": oct(st.st_mode),
                            "uid": st.st_uid,
                            "gid": st.st_gid,
                        },
                        timestamp=report_timestamp,
                    )
                )

            entries = [
                line.strip()
                for line in preload_file.read_text(encoding="utf-8", errors="replace").splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]

            if entries:
                # Any active entry in ld.so.preload is high/critical security risk
                for entry in entries:
                    # Check individual libraries specified in preload
                    so_path = (
                        resolved_root / entry.lstrip("/")
                        if entry.startswith("/")
                        else preload_file.parent / entry
                    )
                    details: dict[str, Any] = {"preload_entry": entry}

                    if so_path.exists():
                        so_st = so_path.lstat()
                        details["exists"] = True
                        details["size"] = so_st.st_size
                        details["uid"] = so_st.st_uid
                        details["gid"] = so_st.st_gid
                        details["mode"] = oct(so_st.st_mode)
                        if is_non_root_writable(so_st, is_real_root=is_real_root):
                            details["non_root_writable"] = True
                    else:
                        details["exists"] = False

                    # Check if preloaded from suspicious directory
                    is_suspicious_location = any(
                        entry.startswith(prefix) for prefix in SUSPICIOUS_DIR_PREFIXES
                    )

                    severity = (
                        Severity.CRITICAL
                        if is_suspicious_location or details.get("non_root_writable")
                        else Severity.HIGH
                    )

                    findings.append(
                        Finding(
                            rule_id=RuleId.PRELOAD001_LD_PRELOAD_ACTIVE.value,
                            severity=severity,
                            path=str(preload_file),
                            message=(
                                f"Active shared object preload hook detected: '{entry}'. "
                                f"In standard clean Linux, ld.so.preload should not contain entries."
                            ),
                            details=details,
                            timestamp=report_timestamp,
                        )
                    )
        except OSError as err:
            findings.append(
                Finding(
                    rule_id=RuleId.PRELOAD001_LD_PRELOAD_ACTIVE.value,
                    severity=Severity.HIGH,
                    path=str(preload_file),
                    message=f"Error reading ld.so.preload: {err}",
                    details={"error": str(err)},
                    timestamp=report_timestamp,
                )
            )

    # 2. Audit /etc/ld.so.conf and /etc/ld.so.conf.d/
    main_ld_conf = resolved_root / "etc/ld.so.conf"
    if main_ld_conf.exists():
        discovered_paths, conf_files = parse_ld_so_conf(main_ld_conf, resolved_root)
        files_checked += len(conf_files)

        # Check permissions of all parsed configuration files
        for conf_p in conf_files:
            try:
                cst = conf_p.lstat()
                if is_non_root_writable(cst, is_real_root=is_real_root):
                    findings.append(
                        Finding(
                            rule_id=RuleId.PRELOAD002_PRELOAD_FILE_WRITABLE.value,
                            severity=Severity.HIGH,
                            path=str(conf_p),
                            message=(
                                f"Dynamic linker configuration file '{conf_p.name}' is writable "
                                f"by non-root users: {oct(cst.st_mode)}"
                            ),
                            details={
                                "mode": oct(cst.st_mode),
                                "uid": cst.st_uid,
                                "gid": cst.st_gid,
                            },
                            timestamp=report_timestamp,
                        )
                    )
            except OSError:
                continue

        # Check library search paths for suspicious directories
        for lib_dir in discovered_paths:
            is_suspicious = any(lib_dir.startswith(pfx) for pfx in SUSPICIOUS_DIR_PREFIXES)
            is_relative = not lib_dir.startswith("/") or lib_dir in (".", "..")

            target_dir = (
                resolved_root / lib_dir.lstrip("/")
                if lib_dir.startswith("/")
                else resolved_root / lib_dir
            )

            is_world_writable = False
            if target_dir.exists():
                try:
                    dst = target_dir.lstat()
                    if is_writable_by_others(dst.st_mode):
                        is_world_writable = True
                except OSError:
                    pass

            if is_suspicious or is_relative or is_world_writable:
                severity = (
                    Severity.CRITICAL if (is_world_writable or is_suspicious) else Severity.HIGH
                )
                msg = f"Suspicious library search directory found in linker configuration: '{lib_dir}'"
                if is_world_writable:
                    msg += " (Directory is world-writable!)"
                if is_relative:
                    msg += " (Relative search paths can lead to arbitrary code execution)"

                findings.append(
                    Finding(
                        rule_id=RuleId.PRELOAD003_SUSPICIOUS_LIB_PATH.value,
                        severity=severity,
                        path=str(main_ld_conf),
                        message=msg,
                        details={
                            "directory": lib_dir,
                            "is_suspicious_location": is_suspicious,
                            "is_relative": is_relative,
                            "is_world_writable": is_world_writable,
                        },
                        timestamp=report_timestamp,
                    )
                )

    # 3. Audit Kernel Module Autoloading: /etc/modules and /etc/modules-load.d/
    module_files_to_check: list[Path] = []
    modules_file = resolved_root / "etc/modules"
    if modules_file.exists():
        module_files_to_check.append(modules_file)

    modules_d = resolved_root / "etc/modules-load.d"
    if modules_d.is_dir():
        for conf in sorted(modules_d.glob("*.conf")):
            if conf.is_file():
                module_files_to_check.append(conf)

    files_checked += len(module_files_to_check)
    for mod_file in module_files_to_check:
        try:
            mst = mod_file.lstat()
            if is_non_root_writable(mst, is_real_root=is_real_root):
                findings.append(
                    Finding(
                        rule_id=RuleId.PRELOAD004_MODULE_CONF_WRITABLE.value,
                        severity=Severity.HIGH,
                        path=str(mod_file),
                        message=(
                            f"Kernel module autoload config '{mod_file.name}' is writable by "
                            f"non-root: {oct(mst.st_mode)}"
                        ),
                        details={"mode": oct(mst.st_mode), "uid": mst.st_uid, "gid": mst.st_gid},
                        timestamp=report_timestamp,
                    )
                )

            lines = mod_file.read_text(encoding="utf-8", errors="replace").splitlines()
            for line in lines:
                mod_name = line.split("#", 1)[0].strip()
                if not mod_name:
                    continue

                clean_name = mod_name.split()[0].lower()
                # Check for known malicious rootkit modules
                if clean_name in KNOWN_ROOTKIT_MODULES:
                    findings.append(
                        Finding(
                            rule_id=RuleId.PRELOAD005_SUSPICIOUS_MODULE.value,
                            severity=Severity.CRITICAL,
                            path=str(mod_file),
                            message=(
                                f"Known rootkit kernel module '{clean_name}' configured for "
                                f"automatic loading in {mod_file.name}!"
                            ),
                            details={"module": clean_name, "raw_entry": mod_name},
                            timestamp=report_timestamp,
                        )
                    )
                # Check if module entry specifies explicit file path (.ko) or unusual paths
                elif "/" in mod_name or mod_name.endswith(".ko"):
                    findings.append(
                        Finding(
                            rule_id=RuleId.PRELOAD005_SUSPICIOUS_MODULE.value,
                            severity=Severity.HIGH,
                            path=str(mod_file),
                            message=(
                                f"Abnormal kernel module path directive in {mod_file.name}: "
                                f"'{mod_name}'"
                            ),
                            details={"module": mod_name},
                            timestamp=report_timestamp,
                        )
                    )
        except OSError as err:
            findings.append(
                Finding(
                    rule_id=RuleId.PRELOAD004_MODULE_CONF_WRITABLE.value,
                    severity=Severity.MEDIUM,
                    path=str(mod_file),
                    message=f"Error reading module configuration {mod_file.name}: {err}",
                    details={"error": str(err)},
                    timestamp=report_timestamp,
                )
            )

    # 4. Audit Process Environment (LD_PRELOAD / LD_LIBRARY_PATH)
    env_preload = os.environ.get("LD_PRELOAD")
    if env_preload:
        findings.append(
            Finding(
                rule_id=RuleId.PRELOAD006_ENV_PRELOAD_SET.value,
                severity=Severity.CRITICAL,
                path="ENV:LD_PRELOAD",
                message=f"LD_PRELOAD environment variable is actively set: '{env_preload}'",
                details={"env_value": env_preload},
                timestamp=report_timestamp,
            )
        )

    env_libpath = os.environ.get("LD_LIBRARY_PATH")
    if env_libpath:
        for part in env_libpath.split(":"):
            if part and (
                any(part.startswith(pfx) for pfx in SUSPICIOUS_DIR_PREFIXES)
                or not part.startswith("/")
            ):
                findings.append(
                    Finding(
                        rule_id=RuleId.PRELOAD006_ENV_PRELOAD_SET.value,
                        severity=Severity.HIGH,
                        path="ENV:LD_LIBRARY_PATH",
                        message=f"Insecure directory in LD_LIBRARY_PATH: '{part}'",
                        details={"path": part, "full_env": env_libpath},
                        timestamp=report_timestamp,
                    )
                )

    duration = time.perf_counter() - start_time
    return AuditReport(
        report_type="preload_audit",
        target_path=str(resolved_root),
        timestamp=report_timestamp,
        duration_seconds=duration,
        total_files_checked=files_checked,
        findings=findings,
    )
