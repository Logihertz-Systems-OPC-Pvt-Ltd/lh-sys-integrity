# ==============================================================================
# Product:       lh-sys-integrity (lh-sys)
# Module:        src.lh_sys_integrity.exporters.table
# Role:          Core Security Engine Component
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Rich terminal table renderer for file integrity and preload audit reports."""

from __future__ import annotations

import io

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from lh_sys_integrity.models import AuditReport, Severity

SEVERITY_STYLES = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "cyan",
}


def render_report_table(report: AuditReport, console: Console | None = None) -> str:
    """Render an AuditReport as a formatted Rich table string or print to console.

    Args:
        report: The AuditReport to render.
        console: Optional Rich Console. If None, uses an in-memory string console.

    Returns:
        Rendered string representation of the report tables.
    """
    capture_console = False
    if console is None:
        string_io = io.StringIO()
        console = Console(file=string_io, force_terminal=True, width=120)
        capture_console = True

    # 1. Summary Header Panel
    status_text = (
        Text("✔ INTEGRITY INTACT - NO TAMPERING DETECTED", style="bold green")
        if report.is_clean
        else Text("✖ INTEGRITY VIOLATIONS DETECTED", style="bold red")
    )

    summary_table = Table.grid(padding=(0, 2))
    summary_table.add_column(style="bold cyan")
    summary_table.add_column()

    summary_table.add_row("Report Type:", report.report_type.upper().replace("_", " "))
    summary_table.add_row("Target Path:", report.target_path)
    summary_table.add_row("Timestamp:", report.timestamp)
    summary_table.add_row("Duration:", f"{report.duration_seconds:.4f} seconds")
    summary_table.add_row("Entities Evaluated:", str(report.total_files_checked))

    findings_summary = (
        f"Critical: [bold red]{report.critical_count}[/] | "
        f"High: [red]{report.high_count}[/] | "
        f"Medium: [yellow]{report.medium_count}[/] | "
        f"Low: [blue]{report.low_count}[/]"
    )
    summary_table.add_row("Findings Breakdown:", findings_summary)

    panel = Panel(
        summary_table,
        title=f"[bold white]lh-fim Security Audit[/] - {status_text.markup}",
        border_style="green" if report.is_clean else "red",
        expand=False,
    )
    console.print(panel)

    # 2. Findings Table
    if report.findings:
        table = Table(
            title="Integrity & Rootkit Findings",
            border_style="bright_black",
            header_style="bold magenta",
            show_lines=True,
        )
        table.add_column("Severity", justify="center", width=12)
        table.add_column("Rule ID", style="cyan", width=28)
        table.add_column("Path", style="yellow", width=30)
        table.add_column("Description / Anomaly Details", style="white")

        for finding in report.findings:
            sev_style = SEVERITY_STYLES.get(finding.severity, "white")
            sev_text = Text(finding.severity.value, style=sev_style)
            table.add_row(
                sev_text,
                finding.rule_id,
                finding.path,
                finding.message,
            )

        console.print(table)
    else:
        console.print("\n[bold green]No security drift, tampering, or rootkit hooks found.[/]\n")

    if capture_console:
        return console.file.getvalue()  # type: ignore[attr-defined]
    return ""
