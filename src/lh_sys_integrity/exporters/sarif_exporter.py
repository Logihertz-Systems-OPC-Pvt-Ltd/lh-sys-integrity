# ==============================================================================
# Product:       lh-sys-integrity (lh-sys)
# Module:        src.lh_sys_integrity.exporters.sarif_exporter
# Role:          SARIF, JSON & Rich Terminal Table Exporters
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""OASIS SARIF v2.1.0 exporter for file integrity and preload rootkit findings."""

from __future__ import annotations

import json
from typing import Any

from lh_sys_integrity.models import AuditReport, RuleId, Severity

SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)
SARIF_VERSION = "2.1.0"
TOOL_NAME = "lh-sys-integrity"
TOOL_VERSION = "0.1.0"
TOOL_INFO_URI = "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-sys-integrity"

RULE_DEFINITIONS: dict[str, dict[str, Any]] = {
    RuleId.FIM001_CONTENT_MODIFIED.value: {
        "id": RuleId.FIM001_CONTENT_MODIFIED.value,
        "name": "FileContentModified",
        "shortDescription": {"text": "Cryptographic file content hash mismatch detected."},
        "fullDescription": {
            "text": "The cryptographic hash of the live file does not match the established baseline manifest, indicating unauthorized tampering, corruption, or replacement."
        },
        "defaultConfiguration": {"level": "error"},
        "helpUri": f"{TOOL_INFO_URI}#fim001",
    },
    RuleId.FIM002_FILE_INJECTED.value: {
        "id": RuleId.FIM002_FILE_INJECTED.value,
        "name": "UnauthorizedFileInjected",
        "shortDescription": {"text": "Unauthorized or newly injected file detected."},
        "fullDescription": {
            "text": "A file was discovered in the live filesystem that was not present in the cryptographic baseline manifest."
        },
        "defaultConfiguration": {"level": "error"},
        "helpUri": f"{TOOL_INFO_URI}#fim002",
    },
    RuleId.FIM003_FILE_DELETED.value: {
        "id": RuleId.FIM003_FILE_DELETED.value,
        "name": "CriticalFileDeleted",
        "shortDescription": {"text": "Critical baselined file has been deleted."},
        "fullDescription": {
            "text": "A file recorded in the cryptographic baseline manifest is missing from the live filesystem."
        },
        "defaultConfiguration": {"level": "error"},
        "helpUri": f"{TOOL_INFO_URI}#fim003",
    },
    RuleId.FIM004_PERM_TAMPERED.value: {
        "id": RuleId.FIM004_PERM_TAMPERED.value,
        "name": "FilePermissionsTampered",
        "shortDescription": {"text": "File permissions or mode bits altered."},
        "fullDescription": {
            "text": "The permission mode of a file has drifted from the baseline, such as gaining world-writable or SUID/SGID privilege escalation privileges."
        },
        "defaultConfiguration": {"level": "error"},
        "helpUri": f"{TOOL_INFO_URI}#fim004",
    },
    RuleId.FIM005_OWNERSHIP_TAMPERED.value: {
        "id": RuleId.FIM005_OWNERSHIP_TAMPERED.value,
        "name": "FileOwnershipTampered",
        "shortDescription": {"text": "UID or GID ownership modified."},
        "fullDescription": {
            "text": "The numeric UID or GID ownership of a file has been changed from the baseline manifest."
        },
        "defaultConfiguration": {"level": "warning"},
        "helpUri": f"{TOOL_INFO_URI}#fim005",
    },
    RuleId.FIM006_TIMESTOMPING_DETECTED.value: {
        "id": RuleId.FIM006_TIMESTOMPING_DETECTED.value,
        "name": "TimestompingDetected",
        "shortDescription": {"text": "Suspicious timestamp backdating or preservation detected."},
        "fullDescription": {
            "text": "The modification timestamp (mtime) of a file is older than the baseline or older than ctime, indicating anti-forensic timestomping."
        },
        "defaultConfiguration": {"level": "error"},
        "helpUri": f"{TOOL_INFO_URI}#fim006",
    },
    RuleId.FIM007_TYPE_DRIFT.value: {
        "id": RuleId.FIM007_TYPE_DRIFT.value,
        "name": "FileTypeDrift",
        "shortDescription": {"text": "Filesystem entity type drift detected."},
        "fullDescription": {
            "text": "The inode file type has changed (e.g., regular file replaced by symlink or special file)."
        },
        "defaultConfiguration": {"level": "error"},
        "helpUri": f"{TOOL_INFO_URI}#fim007",
    },
    RuleId.FIM008_MANIFEST_TAMPERED.value: {
        "id": RuleId.FIM008_MANIFEST_TAMPERED.value,
        "name": "BaselineManifestTampered",
        "shortDescription": {"text": "Baseline manifest cryptographic checksum failure."},
        "fullDescription": {
            "text": "The baseline manifest internal SHA-256 checksum does not match its contents, indicating tampering."
        },
        "defaultConfiguration": {"level": "error"},
        "helpUri": f"{TOOL_INFO_URI}#fim008",
    },
    RuleId.PRELOAD001_LD_PRELOAD_ACTIVE.value: {
        "id": RuleId.PRELOAD001_LD_PRELOAD_ACTIVE.value,
        "name": "LdPreloadHookActive",
        "shortDescription": {
            "text": "Active preload shared object hook detected in ld.so.preload."
        },
        "fullDescription": {
            "text": "An active shared object is registered in /etc/ld.so.preload, allowing arbitrary userland system call hooking."
        },
        "defaultConfiguration": {"level": "error"},
        "helpUri": f"{TOOL_INFO_URI}#preload001",
    },
    RuleId.PRELOAD002_PRELOAD_FILE_WRITABLE.value: {
        "id": RuleId.PRELOAD002_PRELOAD_FILE_WRITABLE.value,
        "name": "LinkerConfigFileWritable",
        "shortDescription": {"text": "Dynamic linker configuration file is writable by non-root."},
        "fullDescription": {
            "text": "A linker configuration file (/etc/ld.so.preload, /etc/ld.so.conf) allows write access to non-root users."
        },
        "defaultConfiguration": {"level": "error"},
        "helpUri": f"{TOOL_INFO_URI}#preload002",
    },
    RuleId.PRELOAD003_SUSPICIOUS_LIB_PATH.value: {
        "id": RuleId.PRELOAD003_SUSPICIOUS_LIB_PATH.value,
        "name": "SuspiciousLibraryPath",
        "shortDescription": {
            "text": "Insecure or suspicious directory in dynamic linker configuration."
        },
        "fullDescription": {
            "text": "A world-writable or temporary directory (/tmp, /dev/shm, relative path) is configured in dynamic linker paths."
        },
        "defaultConfiguration": {"level": "error"},
        "helpUri": f"{TOOL_INFO_URI}#preload003",
    },
    RuleId.PRELOAD004_MODULE_CONF_WRITABLE.value: {
        "id": RuleId.PRELOAD004_MODULE_CONF_WRITABLE.value,
        "name": "ModuleConfigFileWritable",
        "shortDescription": {
            "text": "Kernel module autoload configuration is writable by non-root."
        },
        "fullDescription": {
            "text": "Kernel module autoload configuration file allows write access by unprivileged users."
        },
        "defaultConfiguration": {"level": "error"},
        "helpUri": f"{TOOL_INFO_URI}#preload004",
    },
    RuleId.PRELOAD005_SUSPICIOUS_MODULE.value: {
        "id": RuleId.PRELOAD005_SUSPICIOUS_MODULE.value,
        "name": "SuspiciousKernelModule",
        "shortDescription": {
            "text": "Known rootkit or abnormal kernel module configured for autoload."
        },
        "fullDescription": {
            "text": "A known malicious rootkit LKM or unusual path was detected in /etc/modules or /etc/modules-load.d/."
        },
        "defaultConfiguration": {"level": "error"},
        "helpUri": f"{TOOL_INFO_URI}#preload005",
    },
    RuleId.PRELOAD006_ENV_PRELOAD_SET.value: {
        "id": RuleId.PRELOAD006_ENV_PRELOAD_SET.value,
        "name": "EnvironmentPreloadSet",
        "shortDescription": {
            "text": "LD_PRELOAD or insecure LD_LIBRARY_PATH environment variable set."
        },
        "fullDescription": {
            "text": "The execution environment has LD_PRELOAD or dangerous paths in LD_LIBRARY_PATH actively defined."
        },
        "defaultConfiguration": {"level": "error"},
        "helpUri": f"{TOOL_INFO_URI}#preload006",
    },
}


def severity_to_sarif_level(severity: Severity) -> str:
    """Map internal Severity to SARIF level (error, warning, note)."""
    if severity in (Severity.CRITICAL, Severity.HIGH):
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def export_report_sarif(report: AuditReport) -> str:
    """Export an AuditReport conforming to the OASIS SARIF v2.1.0 standard.

    Args:
        report: AuditReport containing findings to serialize.

    Returns:
        JSON string conforming to SARIF v2.1.0.
    """
    rules_in_report: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []

    for finding in report.findings:
        rule_def = RULE_DEFINITIONS.get(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.rule_id,
                "shortDescription": {"text": finding.message},
                "defaultConfiguration": {"level": severity_to_sarif_level(finding.severity)},
            },
        )
        rules_in_report[finding.rule_id] = rule_def

        result_item: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": severity_to_sarif_level(finding.severity),
            "message": {"text": finding.message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.path.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%",
                        }
                    }
                }
            ],
            "properties": {
                "severity": finding.severity.value,
                "details": finding.details,
            },
        }
        sarif_results.append(result_item)

    sarif_doc = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": TOOL_NAME,
                        "version": TOOL_VERSION,
                        "semanticVersion": TOOL_VERSION,
                        "informationUri": TOOL_INFO_URI,
                        "rules": list(rules_in_report.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    return json.dumps(sarif_doc, indent=2, sort_keys=True)
