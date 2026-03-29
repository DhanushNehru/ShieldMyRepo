"""
ShieldMyRepo CLI — Main entry point.

Usage:
    shieldmyrepo scan <path> [--badge] [--format json] [--scanners name1,name2] [-v]
    shieldmyrepo list
"""

import os
import time

import click
from rich.console import Console

from shieldmyrepo import __version__
from shieldmyrepo.badge import generate_badge
from shieldmyrepo.report import calculate_grade, render_report, save_report
from shieldmyrepo.scanner_registry import ScannerRegistry

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="ShieldMyRepo")
def main():
    """🛡️ ShieldMyRepo — Scan any repo for security nightmares in 30 seconds."""
    pass


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--badge", is_flag=True, help="Generate an SVG badge")
@click.option(
    "--format", "output_format", type=click.Choice(["terminal", "json"]),
    default="terminal", help="Output format"
)
@click.option(
    "--scanners", "scanner_names", default=None,
    help="Comma-separated list of scanner names to run"
)
@click.option(
    "--output", "output_dir", default="reports",
    help="Output directory for reports and badges"
)
@click.option(
    "-v", "--verbose", is_flag=True,
    help="Show detailed output including files scanned and timing"
)
def scan(path, badge, output_format, scanner_names, output_dir, verbose):
    """Scan a repository for security issues.

    PATH is the path to the repository to scan.
    """
    repo_path = os.path.abspath(path)

    console.print(f"\n🛡️ Scanning [bold cyan]{repo_path}[/bold cyan]...\n")

    # Discover and run scanners
    registry = ScannerRegistry()
    registry.discover()

    names = None
    if scanner_names:
        names = [n.strip() for n in scanner_names.split(",")]

    scanners = registry.get_scanners(names)

    if not scanners:
        console.print("[red]No scanners found![/red]")
        console.print("Make sure scanner modules exist in shieldmyrepo/scanners/")
        return

    # Run all scanners
    results = []
    total_files = 0
    
    for scanner in scanners:
        if verbose:
            console.print(f"🔍 Running [cyan]{scanner.name}[/cyan]...")
            start_time = time.perf_counter()
        
        with console.status(f"Running [cyan]{scanner.name}[/cyan]..."):
            result = scanner.run(repo_path)
            results.append(result)
        
        if verbose:
            elapsed = time.perf_counter() - start_time
            files_count = len(result.get("findings", [])) if isinstance(result, dict) else len(result.findings)
            total_files += files_count
            console.print(f"  ✅ {scanner.name}: scanned {files_count} files in {elapsed:.2f}s")

    # Verbose summary
    if verbose:
        console.print(f"\n📊 [bold]Summary:[/bold]")
        console.print(f"  • Total files scanned: {total_files}")
        console.print(f"  • Scanners run: {len(scanners)}")

    # Render report
    report_data = render_report(results, repo_path)

    # Save report if JSON format
    if output_format == "json":
        filepath = save_report(report_data, output_dir)
        console.print(f"📋 Report saved to [cyan]{filepath}[/cyan]")

    # Generate badge if requested
    if badge:
        grade, _, _ = calculate_grade(results)
        badge_path = generate_badge(grade, output_dir)
        console.print(f"🏷️ Badge saved to [cyan]{badge_path}[/cyan]")

    console.print()


@main.command(name="list")
def list_scanners():
    """List all available scanner modules."""
    registry = ScannerRegistry()
    registry.discover()

    scanners = registry.list_scanners()

    if not scanners:
        console.print("[yellow]No scanners found.[/yellow]")
        return

    console.print("\n🔍 [bold]Available Scanners:[/bold]\n")
    for scanner in scanners:
        console.print(f"  • [cyan]{scanner['name']}[/cyan] — {scanner['description']}")
    console.print()


if __name__ == "__main__":
    main()
