
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import box

from graphshield.config import (
    BLOOM_PATH,
    DB_PATH,
    GRAPHSHIELD_DIR,
    GROQ_API_KEY,
)

app = typer.Typer(
    name="graphshield",
    help="🛡️  GraphShield — Agentic Vulnerability Intelligence Engine",
    rich_markup_mode="rich",
    no_args_is_help=True,
)

console = Console(stderr=False)
err_console = Console(stderr=True, style="bold red")

def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(name)s: %(message)s",
    )

@app.command()
def init(
    years: str = typer.Option(
        "2020,2021,2022,2023,2024",
        "--years",
        help="Comma-separated NVD feed years to ingest",
    ),
    force: bool = typer.Option(
        False, "--force", "-f", help="Re-download even if DB already exists"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    _setup_logging(verbose)

    console.print(Panel.fit(
        "[bold cyan]GraphShield[/bold cyan] — initialising...",
        border_style="cyan",
    ))

    try:
        year_list = [int(y.strip()) for y in years.split(",") if y.strip()]
    except ValueError:
        err_console.print(f"Invalid --years value: {years!r}. Use comma-separated integers.")
        raise typer.Exit(code=1)

    GRAPHSHIELD_DIR.mkdir(parents=True, exist_ok=True)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        tid = progress.add_task("Ingesting NVD CVE feeds…", total=None)
        try:
            from graphshield.data.nvd_ingestion import ingest_nvd_feeds
            count = ingest_nvd_feeds(
                db_path=DB_PATH,
                years=year_list,
                full_refresh=force,
            )
            progress.update(tid, description=f"[green]NVD feed — {count} CVEs ingested[/green]")
        except Exception as exc:
            progress.stop()
            err_console.print(f"NVD ingestion failed: {exc}")
            raise typer.Exit(code=1)

        progress.update(tid, description="Building Bloom filter…")
        try:
            _build_bloom_filter(DB_PATH, BLOOM_PATH)
            progress.update(tid, description="[green]Bloom filter built[/green]")
        except Exception as exc:
            progress.stop()
            err_console.print(f"Bloom filter build failed: {exc}")
            raise typer.Exit(code=1)

    console.print("[bold green]✓[/bold green] GraphShield initialised successfully.")
    console.print(f"  DB path:    [dim]{DB_PATH}[/dim]")
    console.print(f"  Bloom path: [dim]{BLOOM_PATH}[/dim]")

def _build_bloom_filter(db_path: Path, bloom_path: Path) -> None:
    import sqlite3
    from graphshield.core.bloom_filter import BloomFilter

    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute("SELECT DISTINCT package_name FROM cve_entries")
    packages = [row[0] for row in cur.fetchall() if row[0]]
    conn.close()

    n = max(len(packages), 1000)
    bf = BloomFilter(expected_items=n, false_positive_rate=0.001)
    for pkg in packages:
        bf.add(pkg.lower().replace("-", "_"))
        bf.add(pkg)

    bf.save(bloom_path)
    logging.getLogger(__name__).info(
        "Bloom filter built with %d package entries → %s", len(packages), bloom_path
    )

@app.command()
def scan(
    target: str = typer.Argument(
        ...,
        help="Local path or GitHub URL (https://github.com/owner/repo)",
    ),
    output: str = typer.Option(
        "", "--output", "-o", help="Output format: json or markdown"
    ),
    markdown: Optional[Path] = typer.Option(
        None, "--markdown", "-m", help="Write Markdown report to this file"
    ),
    no_agent: bool = typer.Option(
        False, "--no-agent", help="Skip LLM patch agent (faster)"
    ),
    api_key: str = typer.Option(
        GROQ_API_KEY, "--api-key", envvar="GROQ_API_KEY",
        help="Groq API key for LLM patch recommendations",
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
    fail_on: str = typer.Option(
        "CRITICAL", "--fail-on",
        help="Exit with code 1 if risk reaches this level (MEDIUM|HIGH|CRITICAL)",
    ),
) -> None:
    _setup_logging(verbose)
    output_mode = output.lower().strip()
    if output_mode in {"json", "markdown"}:
        logging.getLogger().setLevel(logging.ERROR)

    if output_mode not in {"json", "markdown"}:
        console.print(Panel.fit(
            f"[bold cyan]Scanning[/bold cyan] [white]{target}[/white]",
            border_style="cyan",
        ))

        if not DB_PATH.exists():
            console.print(
                "[yellow]⚠[/yellow]  Database not found. Run [bold]graphshield init[/bold] first for CVE data."
            )

    if output_mode in {"json", "markdown"}:
        try:
            from graphshield.core.scanner import GraphShieldScanner
            scanner = GraphShieldScanner(
                groq_api_key=api_key,
                use_agent=(not no_agent) and bool(api_key),
            )
            report = scanner.scan(target)
        except Exception as exc:
            err_console.print(f"Scan failed: {exc}")
            if verbose:
                import traceback; traceback.print_exc()
            raise typer.Exit(code=2)
    else:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
            transient=True,
        ) as progress:
            tid = progress.add_task("Running scan pipeline…", total=None)

            try:
                from graphshield.core.scanner import GraphShieldScanner
                scanner = GraphShieldScanner(
                    groq_api_key=api_key,
                    use_agent=(not no_agent) and bool(api_key),
                )
                report = scanner.scan(target)
            except Exception as exc:
                progress.stop()
                err_console.print(f"Scan failed: {exc}")
                if verbose:
                    import traceback; traceback.print_exc()
                raise typer.Exit(code=2)

            progress.update(tid, description="[green]Scan complete[/green]")

    if output_mode == "json":
        typer.echo(report.to_json())
        _risk_rank = {"CLEAN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        threshold = _risk_rank.get(fail_on.upper(), 4)
        actual = _risk_rank.get(report.risk_summary, 0)
        if actual >= threshold:
            raise typer.Exit(code=1)
        raise typer.Exit(code=0)
    if output_mode == "markdown":
        typer.echo(report.to_markdown())
        _risk_rank = {"CLEAN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        threshold = _risk_rank.get(fail_on.upper(), 4)
        actual = _risk_rank.get(report.risk_summary, 0)
        if actual >= threshold:
            raise typer.Exit(code=1)
        raise typer.Exit(code=0)

    _render_scan_summary(report)

    if output and output_mode not in {"json", "markdown"}:
        out_path = Path(output)
        out_path.write_text(report.to_json(), encoding="utf-8")
        console.print(f"[dim]JSON report → {out_path}[/dim]")

    if markdown:
        markdown.write_text(report.to_markdown(), encoding="utf-8")
        console.print(f"[dim]Markdown report → {markdown}[/dim]")

    _risk_rank = {"CLEAN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    threshold = _risk_rank.get(fail_on.upper(), 4)
    actual = _risk_rank.get(report.risk_summary, 0)
    if actual >= threshold:
        raise typer.Exit(code=1)

def _render_scan_summary(report: "ScanReport") -> None:
    from graphshield.core.scanner import ScanReport

    badge = {
        "CLEAN":    "[bold green]✓ CLEAN[/bold green]",
        "LOW":      "[bold blue]⬤ LOW[/bold blue]",
        "MEDIUM":   "[bold yellow]⬤ MEDIUM[/bold yellow]",
        "HIGH":     "[bold dark_orange]⬤ HIGH[/bold dark_orange]",
        "CRITICAL": "[bold red]⬤ CRITICAL[/bold red]",
    }.get(report.risk_summary, report.risk_summary)

    console.print()
    console.print(f"  Risk level:  {badge}")
    console.print()

    t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
    t.add_column("Metric", style="dim", width=32)
    t.add_column("Value", justify="right")

    t.add_row("Total packages", str(report.total_packages))
    t.add_row("Vulnerable packages", str(report.vulnerable_packages))
    t.add_row("Critical CVEs", f"[bold red]{report.critical_count}[/bold red]")
    t.add_row("High CVEs", f"[orange1]{report.high_count}[/orange1]")
    t.add_row("Medium CVEs", f"[yellow]{report.medium_count}[/yellow]")
    t.add_row("Circular trust clusters", str(len(report.circular_trust_clusters)))
    t.add_row(
        "Minimum packages to update",
        f"[bold]{report.minimum_patch_set.packages_to_update_count}[/bold]"
        f" / {report.minimum_patch_set.total_vulnerable_count}",
    )
    t.add_row("Scan duration", f"{report.scan_duration_seconds}s")
    console.print(t)

    if report.blast_radius_results:
        console.print()
        console.print("[bold]Top Vulnerabilities[/bold]")
        vt = Table(box=box.SIMPLE, show_header=True, header_style="cyan")
        vt.add_column("Package", style="white")
        vt.add_column("CVSS", justify="right")
        vt.add_column("Blast Radius", justify="right")
        vt.add_column("Sensitivity")

        for r in report.blast_radius_results[:5]:
            cvss_str = (
                f"[bold red]{r.cvss_score}[/bold red]" if r.cvss_score >= 9.0
                else f"[orange1]{r.cvss_score}[/orange1]" if r.cvss_score >= 7.0
                else f"[yellow]{r.cvss_score}[/yellow]"
            )
            vt.add_row(
                f"[bold]{r.source_node}[/bold]",
                cvss_str,
                str(r.reachable_count),
                r.data_sensitivity,
            )
        console.print(vt)

    mps = report.minimum_patch_set
    if mps.packages_to_update:
        console.print()
        console.print(
            f"[bold]Minimum Patch Set[/bold]  "
            f"[dim]({mps.savings_percent:.1f}% fewer updates than naive)[/dim]"
        )
        for i, pkg in enumerate(mps.update_order, 1):
            console.print(f"  {i}. [cyan]{pkg}[/cyan]")

@app.command()
def watch(
    path: Path = typer.Argument(
        Path("."), help="Directory to watch (default: current directory)"
    ),
    webhook: str = typer.Option("", "--webhook", "-w", help="Webhook URL for alerts"),
    github_token: str = typer.Option(
        os.getenv("GITHUB_TOKEN", ""), "--github-token", envvar="GITHUB_TOKEN"
    ),
    github_repo: str = typer.Option(
        "", "--github-repo", help="owner/repo for GitHub issue creation"
    ),
    min_severity: str = typer.Option(
        "HIGH", "--min-severity", help="Minimum severity to dispatch (INFO|MEDIUM|HIGH|CRITICAL)"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    _setup_logging(verbose)
    console.print(Panel.fit(
        f"[bold cyan]Watchdog[/bold cyan] monitoring [white]{path}[/white]",
        border_style="cyan",
    ))

    from graphshield.agents.watchdog_agent import WatchdogAgent

    agent = WatchdogAgent(
        watch_roots=[path.resolve()],
        webhook_url=webhook,
        github_token=github_token,
        github_repo=github_repo,
        min_severity=min_severity,
    )

    agent.run_until_interrupted()
    console.print("[dim]Watchdog stopped.[/dim]")

@app.command()
def status(
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    _setup_logging(verbose)

    console.print("[bold cyan]GraphShield Status[/bold cyan]")
    console.print()

    t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
    t.add_column("Component", style="dim", width=24)
    t.add_column("Status")
    t.add_column("Details")

    if DB_PATH.exists():
        try:
            import sqlite3
            conn = sqlite3.connect(str(DB_PATH))
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM cve_entries")
            count = cur.fetchone()[0]
            conn.close()
            db_status = "[green]✓ Ready[/green]"
            db_detail = f"{count:,} CVE entries"
        except Exception as exc:
            db_status = "[red]✗ Error[/red]"
            db_detail = str(exc)
    else:
        db_status = "[yellow]⚠ Not initialised[/yellow]"
        db_detail = f"Run [bold]graphshield init[/bold] first"

    t.add_row("CVE Database", db_status, db_detail)

    if BLOOM_PATH.exists():
        try:
            from graphshield.core.bloom_filter import BloomFilter
            bf = BloomFilter.load(BLOOM_PATH)
            s = bf.stats()
            bloom_status = "[green]✓ Ready[/green]"
            bloom_detail = (
                f"{s['items_added']:,} entries, "
                f"FP rate ≈ {s['estimated_fp_rate']:.4f}"
            )
        except Exception as exc:
            bloom_status = "[red]✗ Error[/red]"
            bloom_detail = str(exc)
    else:
        bloom_status = "[yellow]⚠ Not built[/yellow]"
        bloom_detail = "Run [bold]graphshield init[/bold]"

    t.add_row("Bloom Filter", bloom_status, bloom_detail)

    if GROQ_API_KEY:
        t.add_row("Groq API Key", "[green]✓ Set[/green]", "[dim]●●●●●●●●[/dim]")
    else:
        t.add_row(
            "Groq API Key",
            "[yellow]⚠ Not set[/yellow]",
            "Set GROQ_API_KEY for LLM recommendations",
        )

    console.print(t)

from graphshield.core.scanner import ScanReport

def main() -> None:
    app()

if __name__ == "__main__":
    main()
