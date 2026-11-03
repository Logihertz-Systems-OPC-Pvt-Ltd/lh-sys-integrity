# ==============================================================================
# Product:       lh-sys-integrity (lh-sys)
# Module:        src.lh_sys_integrity.cli
# Role:          CLI Interface & Execution Controller
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Command-line interface for lh-sys-integrity (lh-fim)."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from lh_sys_integrity.baseline import create_baseline, load_baseline, save_baseline
from lh_sys_integrity.exporters.json_exporter import export_report_json
from lh_sys_integrity.exporters.sarif_exporter import export_report_sarif
from lh_sys_integrity.exporters.table import render_report_table
from lh_sys_integrity.models import HashAlgorithm, OutputFormat
from lh_sys_integrity.preload import audit_preload
from lh_sys_integrity.verifier import verify_filesystem

# --- Exit Code Semantics ---
# Exit Code 0: Audit passed successfully with zero policy violations.
# Exit Code 1: Security findings detected meeting or exceeding failure threshold (--fail-on).
# Exit Code 2: Command execution error, invalid arguments, or unparseable input target.

app = typer.Typer(
    name="lh-fim",
    help="Logihertz Systems - Host-based File Integrity Monitoring (FIM) & Intrusion Detection CLI",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)


@app.command(name="init")
def init_command(
    path: Annotated[
        Path,
        typer.Argument(
            help="Target directory or file path to baseline.",
            exists=True,
            resolve_path=True,
        ),
    ],
    algorithm: Annotated[
        HashAlgorithm,
        typer.Option(
            "--algorithm",
            "-a",
            help="Cryptographic hashing algorithm (sha256, sha512, blake2b).",
            case_sensitive=False,
        ),
    ] = HashAlgorithm.SHA256,
    exclude: Annotated[
        list[str] | None,
        typer.Option(
            "--exclude",
            "-e",
            help="Glob pattern to exclude (can be specified multiple times).",
        ),
    ] = None,
    output: Annotated[
        Path,
        typer.Option(
            "--output",
            "-o",
            help="Destination path for the baseline JSON manifest.",
        ),
    ] = Path("baseline.json"),
) -> None:
    """Generate a deterministic, cryptographically signed/checksummed baseline manifest."""
    try:
        manifest = create_baseline(target_path=path, algorithm=algorithm, excludes=exclude)
        save_baseline(manifest, output)
        console.print(
            f"[bold green]✔ Baseline generated successfully:[/] [cyan]{output}[/] "
            f"({manifest.metadata.file_count} files, algorithm: [yellow]{algorithm.value}[/])"
        )
    except Exception as err:
        err_console.print(f"[bold red]Error generating baseline:[/] {err}")
        raise typer.Exit(code=2) from err


@app.command(name="verify")
def verify_command(
    path: Annotated[
        Path,
        typer.Argument(
            help="Target directory or file path to verify.",
            exists=True,
            resolve_path=True,
        ),
    ],
    baseline: Annotated[
        Path,
        typer.Option(
            "--baseline",
            "-b",
            help="Path to the baseline manifest JSON file.",
            exists=True,
            resolve_path=True,
        ),
    ] = ...,  # type: ignore[assignment]
    format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            help="Output report format (table, json, sarif).",
            case_sensitive=False,
        ),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Optional file path to write findings report.",
        ),
    ] = None,
    exclude: Annotated[
        list[str] | None,
        typer.Option(
            "--exclude",
            "-e",
            help="Glob pattern to exclude from verification.",
        ),
    ] = None,
) -> None:
    """Verify live filesystem states against an established baseline manifest."""
    try:
        manifest = load_baseline(baseline)
    except Exception as err:
        err_console.print(f"[bold red]Failed to load baseline manifest:[/] {err}")
        raise typer.Exit(code=2) from err

    report = verify_filesystem(target_path=path, baseline=manifest, excludes=exclude)

    # Format output
    if format == OutputFormat.TABLE:
        render_report_table(report, console=console)
        if output:
            table_str = render_report_table(report, console=None)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(table_str, encoding="utf-8")
    elif format == OutputFormat.JSON:
        json_output = export_report_json(report)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json_output, encoding="utf-8")
            console.print(f"[green]Report written to:[/] {output}")
        else:
            typer.echo(json_output)
    elif format == OutputFormat.SARIF:
        sarif_output = export_report_sarif(report)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(sarif_output, encoding="utf-8")
            console.print(f"[green]SARIF report written to:[/] {output}")
        else:
            typer.echo(sarif_output)

    # Exit with code 1 if integrity violations are detected
    if not report.is_clean:
        raise typer.Exit(code=1)


@app.command(name="audit-preload")
def audit_preload_command(
    root: Annotated[
        Path,
        typer.Option(
            "--root",
            "-r",
            help="System root directory to audit for preload configurations.",
            resolve_path=True,
        ),
    ] = Path("/"),
    format: Annotated[
        OutputFormat,
        typer.Option(
            "--format",
            "-f",
            help="Output report format (table, json, sarif).",
            case_sensitive=False,
        ),
    ] = OutputFormat.TABLE,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output",
            "-o",
            help="Optional file path to write audit report.",
        ),
    ] = None,
) -> None:
    """Audit Linux dynamic linker, ld.so.preload, and kernel modules for rootkit hooks."""
    report = audit_preload(root_path=root)

    if format == OutputFormat.TABLE:
        render_report_table(report, console=console)
        if output:
            table_str = render_report_table(report, console=None)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(table_str, encoding="utf-8")
    elif format == OutputFormat.JSON:
        json_output = export_report_json(report)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json_output, encoding="utf-8")
            console.print(f"[green]Report written to:[/] {output}")
        else:
            typer.echo(json_output)
    elif format == OutputFormat.SARIF:
        sarif_output = export_report_sarif(report)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(sarif_output, encoding="utf-8")
            console.print(f"[green]SARIF report written to:[/] {output}")
        else:
            typer.echo(sarif_output)

    if not report.is_clean:
        raise typer.Exit(code=1)


def main() -> None:
    """Entry point for lh-fim CLI application."""
    app()


if __name__ == "__main__":
    main()
