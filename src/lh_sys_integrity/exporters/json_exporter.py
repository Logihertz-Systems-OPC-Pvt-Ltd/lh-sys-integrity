# ==============================================================================
# Product:       lh-sys-integrity (lh-sys)
# Module:        src.lh_sys_integrity.exporters.json_exporter
# Role:          SARIF, JSON & Rich Terminal Table Exporters
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""JSON exporter for audit and integrity verification reports."""

from __future__ import annotations

import json

from lh_sys_integrity.models import AuditReport


def export_report_json(report: AuditReport, indent: int = 2) -> str:
    """Serialize an AuditReport to a formatted JSON string.

    Args:
        report: AuditReport instance to serialize.
        indent: Indentation level for pretty-printing.

    Returns:
        JSON string representation.
    """
    return json.dumps(report.to_dict(), indent=indent, sort_keys=True)
