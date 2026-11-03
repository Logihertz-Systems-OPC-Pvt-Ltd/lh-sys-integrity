# ==============================================================================
# Product:       lh-sys-integrity (lh-sys)
# Module:        src.lh_sys_integrity.verifier
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Filesystem state verifier against cryptographic baseline manifests."""

from __future__ import annotations

import os
import stat
import time
from datetime import UTC, datetime
from pathlib import Path

from lh_sys_integrity.baseline import (
    format_mode_octal,
    get_group_name,
    get_user_name,
    is_excluded,
    verify_baseline_checksum,
)
from lh_sys_integrity.hasher import (
    compute_file_hash,
    compute_manifest_checksum,
)
from lh_sys_integrity.models import (
    AuditReport,
    BaselineManifest,
    Finding,
    HashAlgorithm,
    RuleId,
    Severity,
)


def verify_filesystem(
    target_path: Path,
    baseline: BaselineManifest,
    excludes: list[str] | None = None,
) -> AuditReport:
    """Verify the live filesystem state against an established baseline manifest.

    Detects content tampering, unexpected file injections, deletions of critical files,
    permission/ownership alterations, and suspicious timestomping manipulations.

    Args:
        target_path: Root directory or file path to verify.
        baseline: BaselineManifest to compare against.
        excludes: List of glob patterns to exclude from verification.

    Returns:
        AuditReport containing all detected findings and summary metrics.
    """
    start_time = time.perf_counter()
    report_timestamp = datetime.now(UTC).isoformat()
    findings: list[Finding] = []

    # 1. Manifest Tampering Verification
    if not verify_baseline_checksum(baseline):
        findings.append(
            Finding(
                rule_id=RuleId.FIM008_MANIFEST_TAMPERED.value,
                severity=Severity.CRITICAL,
                path=baseline.metadata.target_path,
                message=(
                    "Baseline manifest cryptographic checksum mismatch! The baseline manifest "
                    "has been altered or corrupted since generation."
                ),
                details={
                    "recorded_checksum": baseline.metadata.manifest_checksum,
                    "target_path": baseline.metadata.target_path,
                },
                timestamp=report_timestamp,
            )
        )

    resolved_target = target_path.resolve()
    if not resolved_target.exists():
        findings.append(
            Finding(
                rule_id=RuleId.FIM003_FILE_DELETED.value,
                severity=Severity.CRITICAL,
                path=str(target_path),
                message=f"Scanned target path does not exist on filesystem: {target_path}",
                details={"target_path": str(target_path)},
                timestamp=report_timestamp,
            )
        )
        duration = time.perf_counter() - start_time
        return AuditReport(
            report_type="verification",
            target_path=str(resolved_target),
            timestamp=report_timestamp,
            duration_seconds=duration,
            total_files_checked=0,
            findings=findings,
        )

    # 2. Discover live files
    live_files_map: dict[str, Path] = {}
    if resolved_target.is_file():
        rel = resolved_target.name
        if not is_excluded(rel, excludes):
            live_files_map[rel] = resolved_target
        base_dir = resolved_target.parent
    else:
        base_dir = resolved_target
        for root, dirs, files in os.walk(resolved_target, followlinks=False):
            dirs.sort()
            files.sort()
            for filename in files:
                p = Path(root) / filename
                rel = p.relative_to(base_dir).as_posix()
                if not is_excluded(rel, excludes):
                    live_files_map[rel] = p

    baseline_files = baseline.files
    baseline_rel_paths = set(baseline_files.keys())
    live_rel_paths = set(live_files_map.keys())

    # 3. Detect Deleted Files
    deleted_paths = sorted(baseline_rel_paths - live_rel_paths)
    for del_rel in deleted_paths:
        base_rec = baseline_files[del_rel]
        findings.append(
            Finding(
                rule_id=RuleId.FIM003_FILE_DELETED.value,
                severity=Severity.CRITICAL,
                path=del_rel,
                message=f"Critical baselined file has been removed: {del_rel}",
                details={
                    "baseline_hash": base_rec.hash,
                    "baseline_size": base_rec.size,
                    "baseline_mode": base_rec.mode_octal,
                    "baseline_user": base_rec.user,
                },
                timestamp=report_timestamp,
            )
        )

    # 4. Detect Injected Files
    injected_paths = sorted(live_rel_paths - baseline_rel_paths)
    for inj_rel in injected_paths:
        inj_path = live_files_map[inj_rel]
        try:
            st = inj_path.lstat()
            is_exec = bool(st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
            is_suid = bool(st.st_mode & (stat.S_ISUID | stat.S_ISGID))
            severity = (
                Severity.CRITICAL if is_suid else (Severity.HIGH if is_exec else Severity.MEDIUM)
            )

            findings.append(
                Finding(
                    rule_id=RuleId.FIM002_FILE_INJECTED.value,
                    severity=severity,
                    path=inj_rel,
                    message=f"Unauthorized un-baselined file detected: {inj_rel}",
                    details={
                        "size": st.st_size,
                        "mode": format_mode_octal(st.st_mode),
                        "permissions": stat.filemode(st.st_mode),
                        "uid": st.st_uid,
                        "gid": st.st_gid,
                        "is_executable": is_exec,
                        "is_suid_sgid": is_suid,
                    },
                    timestamp=report_timestamp,
                )
            )
        except OSError as err:
            findings.append(
                Finding(
                    rule_id=RuleId.FIM002_FILE_INJECTED.value,
                    severity=Severity.HIGH,
                    path=inj_rel,
                    message=f"Unauthorized file injected (error reading stats): {err}",
                    details={"error": str(err)},
                    timestamp=report_timestamp,
                )
            )

    # 5. Verify Common Files
    common_paths = sorted(baseline_rel_paths & live_rel_paths)
    algo_name = HashAlgorithm.from_str(baseline.metadata.algorithm or HashAlgorithm.SHA256).value

    for rel_path in common_paths:
        base_rec = baseline_files[rel_path]
        live_path = live_files_map[rel_path]

        try:
            live_st = live_path.lstat()
        except OSError as err:
            findings.append(
                Finding(
                    rule_id=RuleId.FIM001_CONTENT_MODIFIED.value,
                    severity=Severity.HIGH,
                    path=rel_path,
                    message=f"Failed to stat live file {rel_path}: {err}",
                    details={"error": str(err)},
                    timestamp=report_timestamp,
                )
            )
            continue

        # A. Type Drift (e.g. Regular file replaced by symlink or vice-versa)
        base_is_link = stat.S_ISLNK(base_rec.mode)
        live_is_link = stat.S_ISLNK(live_st.st_mode)
        if base_is_link != live_is_link:
            findings.append(
                Finding(
                    rule_id=RuleId.FIM007_TYPE_DRIFT.value,
                    severity=Severity.CRITICAL,
                    path=rel_path,
                    message=(
                        f"File type drift detected for {rel_path}: "
                        f"expected {'symlink' if base_is_link else 'regular file'}, "
                        f"found {'symlink' if live_is_link else 'regular file'}"
                    ),
                    details={
                        "baseline_mode": base_rec.mode_octal,
                        "live_mode": format_mode_octal(live_st.st_mode),
                    },
                    timestamp=report_timestamp,
                )
            )
            continue

        # B. Content Modification Check
        content_tampered = False
        if live_is_link:
            try:
                live_target = os.readlink(live_path)
                expected_target_hash = base_rec.hash
                actual_target_hash = compute_manifest_checksum({"symlink_target": live_target})
                if actual_target_hash != expected_target_hash:
                    content_tampered = True
                    findings.append(
                        Finding(
                            rule_id=RuleId.FIM001_CONTENT_MODIFIED.value,
                            severity=Severity.CRITICAL,
                            path=rel_path,
                            message=f"Symlink target modified for {rel_path}: now points to {live_target}",
                            details={
                                "expected_target_hash": expected_target_hash,
                                "actual_target": live_target,
                            },
                            timestamp=report_timestamp,
                        )
                    )
            except OSError as err:
                findings.append(
                    Finding(
                        rule_id=RuleId.FIM001_CONTENT_MODIFIED.value,
                        severity=Severity.HIGH,
                        path=rel_path,
                        message=f"Failed to read live symlink {rel_path}: {err}",
                        details={"error": str(err)},
                        timestamp=report_timestamp,
                    )
                )
        else:
            try:
                live_hash = compute_file_hash(live_path, algorithm=algo_name)
                if live_hash != base_rec.hash:
                    content_tampered = True
                    findings.append(
                        Finding(
                            rule_id=RuleId.FIM001_CONTENT_MODIFIED.value,
                            severity=Severity.CRITICAL,
                            path=rel_path,
                            message=(
                                f"Cryptographic hash mismatch for {rel_path}: "
                                f"expected {base_rec.hash[:16]}..., got {live_hash[:16]}..."
                            ),
                            details={
                                "algorithm": algo_name,
                                "expected_hash": base_rec.hash,
                                "actual_hash": live_hash,
                                "expected_size": base_rec.size,
                                "actual_size": live_st.st_size,
                            },
                            timestamp=report_timestamp,
                        )
                    )
            except (PermissionError, OSError) as err:
                findings.append(
                    Finding(
                        rule_id=RuleId.FIM001_CONTENT_MODIFIED.value,
                        severity=Severity.HIGH,
                        path=rel_path,
                        message=f"Error computing hash for {rel_path}: {err}",
                        details={"error": str(err)},
                        timestamp=report_timestamp,
                    )
                )

        # C. Permission Drift Check
        base_imode = stat.S_IMODE(base_rec.mode)
        live_imode = stat.S_IMODE(live_st.st_mode)
        if base_imode != live_imode:
            # Check for privilege escalation bits
            added_suid = bool((live_imode & stat.S_ISUID) and not (base_imode & stat.S_ISUID))
            added_sgid = bool((live_imode & stat.S_ISGID) and not (base_imode & stat.S_ISGID))
            added_world_write = bool(
                (live_imode & stat.S_IWOTH) and not (base_imode & stat.S_IWOTH)
            )

            if added_suid or added_sgid:
                perm_severity = Severity.CRITICAL
                perm_msg = f"Privilege escalation bit (SUID/SGID) added to {rel_path}"
            elif added_world_write:
                perm_severity = Severity.HIGH
                perm_msg = f"World-writable permission added to {rel_path}"
            else:
                perm_severity = Severity.MEDIUM
                perm_msg = f"File permission drift detected for {rel_path}"

            findings.append(
                Finding(
                    rule_id=RuleId.FIM004_PERM_TAMPERED.value,
                    severity=perm_severity,
                    path=rel_path,
                    message=f"{perm_msg}: {base_rec.mode_octal} ({base_rec.permissions}) -> {format_mode_octal(live_st.st_mode)} ({stat.filemode(live_st.st_mode)})",
                    details={
                        "expected_mode": base_rec.mode_octal,
                        "actual_mode": format_mode_octal(live_st.st_mode),
                        "expected_permissions": base_rec.permissions,
                        "actual_permissions": stat.filemode(live_st.st_mode),
                        "added_suid": added_suid,
                        "added_sgid": added_sgid,
                        "added_world_write": added_world_write,
                    },
                    timestamp=report_timestamp,
                )
            )

        # D. Ownership Drift Check
        if live_st.st_uid != base_rec.uid or live_st.st_gid != base_rec.gid:
            live_user = get_user_name(live_st.st_uid)
            live_group = get_group_name(live_st.st_gid)
            findings.append(
                Finding(
                    rule_id=RuleId.FIM005_OWNERSHIP_TAMPERED.value,
                    severity=Severity.HIGH,
                    path=rel_path,
                    message=(
                        f"File ownership modified for {rel_path}: "
                        f"{base_rec.uid}:{base_rec.gid} ({base_rec.user}:{base_rec.group}) -> "
                        f"{live_st.st_uid}:{live_st.st_gid} ({live_user}:{live_group})"
                    ),
                    details={
                        "expected_uid": base_rec.uid,
                        "actual_uid": live_st.st_uid,
                        "expected_gid": base_rec.gid,
                        "actual_gid": live_st.st_gid,
                        "expected_user": base_rec.user,
                        "actual_user": live_user,
                        "expected_group": base_rec.group,
                        "actual_group": live_group,
                    },
                    timestamp=report_timestamp,
                )
            )

        # E. Timestomping & Timestamp Anomaly Detection
        # Condition 1: mtime older than baseline (backdated modification timestamp)
        # We allow a tiny sub-millisecond float tolerance (0.001s)
        backdated_mtime = live_st.st_mtime < (base_rec.mtime - 0.001)

        # Condition 2: ctime significantly newer than mtime (hallmark of utimes / touch -d)
        # When an attacker sets mtime in the past, Unix updates ctime to current time
        # so ctime > mtime by more than 1 second indicates backdating.
        ctime_newer_than_mtime = (live_st.st_ctime - live_st.st_mtime) > 1.0

        # Condition 3: Content changed but mtime was miraculously preserved
        content_modified_with_preserved_mtime = (
            content_tampered and abs(live_st.st_mtime - base_rec.mtime) < 0.001
        )

        if (
            backdated_mtime
            or (content_tampered and ctime_newer_than_mtime)
            or content_modified_with_preserved_mtime
        ):
            reason = []
            if backdated_mtime:
                reason.append(
                    f"live mtime ({live_st.st_mtime}) is older than baseline mtime ({base_rec.mtime})"
                )
            if ctime_newer_than_mtime and (content_tampered or backdated_mtime):
                reason.append(
                    f"ctime ({live_st.st_ctime}) is newer than mtime ({live_st.st_mtime}) by {live_st.st_ctime - live_st.st_mtime:.1f}s"
                )
            if content_modified_with_preserved_mtime:
                reason.append("content modified but baseline mtime was artificially preserved")

            if reason:
                findings.append(
                    Finding(
                        rule_id=RuleId.FIM006_TIMESTOMPING_DETECTED.value,
                        severity=Severity.HIGH,
                        path=rel_path,
                        message=f"Suspicious timestomping detected for {rel_path}: {'; '.join(reason)}",
                        details={
                            "live_mtime": live_st.st_mtime,
                            "live_ctime": live_st.st_ctime,
                            "baseline_mtime": base_rec.mtime,
                            "baseline_ctime": base_rec.ctime,
                            "reasons": reason,
                        },
                        timestamp=report_timestamp,
                    )
                )

    duration = time.perf_counter() - start_time
    return AuditReport(
        report_type="verification",
        target_path=str(resolved_target),
        timestamp=report_timestamp,
        duration_seconds=duration,
        total_files_checked=len(common_paths) + len(injected_paths),
        findings=findings,
    )
