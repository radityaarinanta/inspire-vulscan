#!/usr/bin/env python3
"""
Inspire - Standalone Cyber CLI Security Scanner
"""
import sys
import asyncio
import argparse
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.text import Text
from rich import box

from core.models import ScanConfig, ScanProfile, Severity
from core.engine import scanner_engine
from core.reporter import ReportGenerator

console = Console()

BANNER = r"""
[bold yellow]
  ___ _  _ ___ ___ ___ ___ 
 |_ _| \| / __| _ \ |_ _| _ \
  | || .` \__ \  _/ | || |/ /
 |___|_|\_|___/_| |___|_|_\_\
[/bold yellow]
[dim bold]  Enterprise Web Vulnerability Scanner & Security Audit Suite[/dim bold]
[dim yellow]  Version 1.0.0 | OWASP-Aligned | High-Performance Async Engine[/dim yellow]
"""

def print_banner():
    console.print(BANNER)

async def run_cli_scan(url: str, profile_str: str, export_pdf: bool, export_html: bool, export_json: bool = False, export_sarif: bool = False, export_csv: bool = False):
    print_banner()

    # Normalize Profile
    try:
        profile = ScanProfile(profile_str.lower())
    except ValueError:
        profile = ScanProfile.STANDARD

    config = ScanConfig(
        target_url=url,
        profile=profile,
        max_crawl_depth=2,
        max_pages=15
    )

    console.print(Panel(
        f"[bold white]Target URL:[/bold white] [yellow]{config.target_url}[/yellow]\n"
        f"[bold white]Scan Profile:[/bold white] [green]{config.profile.value.upper()}[/green]\n"
        f"[bold white]Started At:[/bold white] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        title="[bold yellow]🚀 Inspire — Scan Initialization[/bold yellow]",
        border_style="yellow"
    ))

    with Progress(
        SpinnerColumn("dots", style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40, style="dim", complete_style="cyan"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    ) as progress_bar:
        
        task = progress_bar.add_task("[cyan]Scanning target...", total=100)

        # Progress update callback
        def cli_progress_listener(msg: dict):
            if msg.get("event") == "progress":
                data = msg.get("data", {})
                pct = data.get("progress_percentage", 0)
                action = data.get("current_action", "Scanning...")
                progress_bar.update(task, completed=pct, description=f"[cyan]{action[:45]}...")

        scanner_engine.subscribe("cli-scan", cli_progress_listener)
        result = await scanner_engine.run_scan(config, scan_id="cli-scan")
        scanner_engine.unsubscribe("cli-scan", cli_progress_listener)
        progress_bar.update(task, completed=100, description="[green]Scan completed!")

    console.print()

    # Summary Panel
    summary = result.summary
    grade_color = "green" if summary.security_grade in ['A+', 'A'] else "yellow" if summary.security_grade == 'B' else "red"

    summary_table = Table(box=box.ROUNDED, show_header=False, border_style="dim")
    summary_table.add_column("Key", style="bold white", width=22)
    summary_table.add_column("Value", style="cyan")

    summary_table.add_row("Overall Security Grade", f"[{grade_color} bold]{summary.security_grade}[/{grade_color} bold]")
    summary_table.add_row("Risk Score", f"{summary.risk_score} / 100")
    summary_table.add_row("Scan Duration", f"{summary.duration_seconds} seconds")
    summary_table.add_row("Pages Analyzed", str(summary.urls_crawled_count))
    summary_table.add_row("Total Vulnerabilities", f"[bold]{summary.total_findings}[/bold]")
    summary_table.add_row("Critical Severity", f"[red bold]{summary.critical_count}[/red bold]")
    summary_table.add_row("High Severity", f"[orange3 bold]{summary.high_count}[/orange3 bold]")
    summary_table.add_row("Medium Severity", f"[yellow bold]{summary.medium_count}[/yellow bold]")
    summary_table.add_row("Low / Info", f"[blue]{summary.low_count + summary.info_count}[/blue]")

    console.print(Panel(summary_table, title="[bold cyan]📊 Security Audit Summary[/bold cyan]", border_style="cyan"))

    # Findings Table
    if result.vulnerabilities:
        findings_table = Table(title="[bold red]🚨 Discovered Vulnerabilities & Weaknesses[/bold red]", box=box.ROUNDED, border_style="red")
        findings_table.add_column("#", style="dim", width=4)
        findings_table.add_column("Severity", width=12)
        findings_table.add_column("Vulnerability Name", style="bold white", width=34)
        findings_table.add_column("CVSS", width=6, justify="center")
        findings_table.add_column("OWASP / Category", style="dim", width=26)
        findings_table.add_column("Remediation Advice", style="green", width=40)

        for idx, v in enumerate(result.vulnerabilities, 1):
            sev_style = "red bold" if v.severity == Severity.CRITICAL else "orange3 bold" if v.severity == Severity.HIGH else "yellow" if v.severity == Severity.MEDIUM else "blue"
            findings_table.add_row(
                str(idx),
                f"[{sev_style}]{v.severity.value}[/{sev_style}]",
                v.name,
                str(v.cvss_score),
                v.owasp_category or v.category,
                v.remediation[:80] + "..." if len(v.remediation) > 80 else v.remediation
            )

        console.print(findings_table)
    else:
        console.print(Panel("[green bold]✓ No vulnerabilities discovered for the selected scan profile.[/green bold]", border_style="green"))

    # Report Export
    reporter = ReportGenerator()
    if export_pdf:
        pdf_path = reporter.generate_pdf_report(result)
        console.print(f"[bold green]✓ Executive PDF Report generated:[/bold green] [cyan]{pdf_path}[/cyan]")
    if export_html:
        html_path = reporter.generate_html_report(result)
        console.print(f"[bold green]✓ Standalone HTML Report generated:[/bold green] [cyan]{html_path}[/cyan]")
    if export_json:
        json_path = reporter.generate_json_report(result)
        console.print(f"[bold green]✓ Structured JSON Report generated:[/bold green] [cyan]{json_path}[/cyan]")
    if export_sarif:
        sarif_path = reporter.generate_sarif_report(result)
        console.print(f"[bold green]✓ OASIS SARIF v2.1.0 Report generated:[/bold green] [cyan]{sarif_path}[/cyan]")
    if export_csv:
        csv_path = reporter.generate_csv_report(result)
        console.print(f"[bold green]✓ Spreadsheet CSV Report generated:[/bold green] [cyan]{csv_path}[/cyan]")

def main():
    parser = argparse.ArgumentParser(description="Inspire - Modern Web Vulnerability Scanner")
    parser.add_argument("url", nargs="?", help="Target website URL (e.g. http://testphp.vulnweb.com)")
    parser.add_argument("-p", "--profile", default="standard", choices=["quick", "standard", "deep"], help="Scan Profile (quick, standard, deep)")
    parser.add_argument("--pdf", action="store_true", help="Generate Executive PDF Report")
    parser.add_argument("--html", action="store_true", help="Generate Standalone HTML Report")
    parser.add_argument("--json", action="store_true", help="Generate Full Structured JSON Report")
    parser.add_argument("--sarif", action="store_true", help="Generate OASIS SARIF v2.1.0 Report (GitHub Security compatible)")
    parser.add_argument("--csv", action="store_true", help="Generate Spreadsheet CSV Report")
    parser.add_argument("--all-reports", action="store_true", help="Generate all 5 report formats simultaneously (PDF, HTML, JSON, SARIF, CSV)")

    args = parser.parse_args()

    target_url = args.url
    if not target_url:
        print_banner()
        target_url = console.input("[bold cyan]Enter Target URL to audit:[/bold cyan] ").strip()
        if not target_url:
            console.print("[red]No target URL specified. Exiting.[/red]")
            sys.exit(1)

    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    export_pdf = args.pdf or args.all_reports
    export_html = args.html or args.all_reports
    export_json = args.json or args.all_reports
    export_sarif = args.sarif or args.all_reports
    export_csv = args.csv or args.all_reports

    asyncio.run(run_cli_scan(
        url=target_url,
        profile_str=args.profile,
        export_pdf=export_pdf,
        export_html=export_html,
        export_json=export_json,
        export_sarif=export_sarif,
        export_csv=export_csv
    ))

if __name__ == "__main__":
    main()
