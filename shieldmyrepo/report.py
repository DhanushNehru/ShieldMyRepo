"""
Report card generator.

Produces beautiful terminal output showing the security grade
and per-scanner results using the Rich library.
"""

import json
import os
from typing import List

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from shieldmyrepo.scanner_registry import ScanResult, Severity


def calculate_grade(results: List[ScanResult]) -> tuple:
    """Calculate the overall security grade from scan results.

    Args:
        results: List of ScanResult objects from all scanners.

    Returns:
        Tuple of (grade letter, numeric score, color).
    """
    base_score = 100
    total_deduction = sum(r.total_score_deduction for r in results)

    score = max(0, base_score - total_deduction)

    if score >= 90:
        return "A", score, "green"
    elif score >= 80:
        return "B", score, "blue"
    elif score >= 70:
        return "C", score, "yellow"
    elif score >= 60:
        return "D", score, "dark_orange"
    else:
        return "F", score, "red"


def render_report(results: List[ScanResult], repo_path: str) -> dict:
    """Render a beautiful terminal report card.

    Args:
        results: List of ScanResult objects.
        repo_path: Path to the scanned repository.

    Returns:
        Report data as a dictionary (for JSON export).
    """
    console = Console()
    grade, score, color = calculate_grade(results)

    # Header
    console.print()
    console.print(
        Panel(
            Text("🛡️ ShieldMyRepo — Security Report Card", justify="center", style="bold white"),
            border_style="bright_blue",
        )
    )

    # Grade display
    grade_text = Text(f"  📊 Overall Grade: {grade} ({score}/100)  ", style=f"bold {color}")
    console.print(Panel(grade_text, border_style=color))

    # Results table
    table = Table(
        title="Scanner Results",
        show_header=True,
        header_style="bold cyan",
        border_style="bright_blue",
    )
    table.add_column("Scanner", style="white", min_width=25)
    table.add_column("Status", justify="center", min_width=10)
    table.add_column("Findings", justify="center", min_width=10)

    status_icons = {
        "PASS": "[green]✅ PASS[/green]",
        "WARN": "[yellow]⚠️  WARN[/yellow]",
        "FAIL": "[red]❌ FAIL[/red]",
    }

    for result in results:
        icon = ""
        if "secret" in result.scanner_name.lower():
            icon = "🔑"
        elif "depend" in result.scanner_name.lower():
            icon = "📦"
        elif "action" in result.scanner_name.lower():
            icon = "⚙️"
        elif "docker" in result.scanner_name.lower():
            icon = "🐳"
        elif "gitignore" in result.scanner_name.lower():
            icon = "📄"
        else:
            icon = "🔍"

        table.add_row(
            f"{icon} {result.scanner_name}",
            status_icons.get(result.status, result.status),
            str(len(result.findings)),
        )

    console.print(table)

    # Detailed findings
    for result in results:
        if result.findings:
            console.print()
            console.print(f"[bold]{result.scanner_name}[/bold] — Findings:", style="white")
            for i, finding in enumerate(result.findings, 1):
                severity_colors = {
                    Severity.CRITICAL: "red bold",
                    Severity.HIGH: "red",
                    Severity.MEDIUM: "yellow",
                    Severity.LOW: "blue",
                    Severity.INFO: "dim",
                }
                sev_style = severity_colors.get(finding.severity, "white")
                location = ""
                if finding.file:
                    location = f" in [cyan]{finding.file}[/cyan]"
                    if finding.line:
                        location += f":[cyan]{finding.line}[/cyan]"

                console.print(
                    f"  {i}. [{sev_style}][{finding.severity.value.upper()}][/{sev_style}]"
                    f" {finding.message}{location}"
                )
                if finding.recommendation:
                    console.print(
                        f"     💡 {finding.recommendation}", style="dim"
                    )

    console.print()

    # Build report data
    report_data = {
        "repository": repo_path,
        "grade": grade,
        "score": score,
        "scanners": [],
    }
    for result in results:
        scanner_data = {
            "name": result.scanner_name,
            "status": result.status,
            "findings": [
                {
                    "severity": f.severity.value,
                    "message": f.message,
                    "file": f.file,
                    "line": f.line,
                    "recommendation": f.recommendation,
                }
                for f in result.findings
            ],
        }
        report_data["scanners"].append(scanner_data)

    return report_data


def render_markdown(report_data: dict) -> str:
    """Render report as Markdown format.

    Args:
        report_data: Report dictionary from render_report.

    Returns:
        Markdown formatted string.
    """
    lines = []
    
    # Header
    lines.append("# 🛡️ ShieldMyRepo — Security Report")
    lines.append("")
    
    # Grade
    grade = report_data["grade"]
    score = report_data["score"]
    grade_colors = {"A": "🟢", "B": "🔵", "C": "🟡", "D": "🟠", "F": "🔴"}
    emoji = grade_colors.get(grade, "⚪")
    
    lines.append(f"## {emoji} Overall Grade: **{grade}** ({score}/100)")
    lines.append("")
    
    # Repository info
    lines.append(f"**Repository**: `{report_data['repository']}`")
    lines.append("")
    
    # Summary table
    lines.append("## Scanner Results")
    lines.append("")
    lines.append("| Scanner | Status | Findings |")
    lines.append("|---------|--------|----------|")
    
    for scanner in report_data["scanners"]:
        status_emoji = {"PASS": "✅", "WARN": "⚠️", "FAIL": "❌"}.get(scanner["status"], "•")
        lines.append(f"| {scanner['name']} | {status_emoji} {scanner['status']} | {len(scanner['findings'])} |")
    
    lines.append("")
    
    # Detailed findings
    for scanner in report_data["scanners"]:
        if scanner["findings"]:
            lines.append(f"### 🔍 {scanner['name']}")
            lines.append("")
            
            for i, finding in enumerate(scanner["findings"], 1):
                severity = finding["severity"].upper()
                location = ""
                if finding.get("file"):
                    location = f" in `{finding['file']}`"
                    if finding.get("line"):
                        location += f":L{finding['line']}"
                
                lines.append(f"**{i}. [{severity}]** {finding['message']}{location}")
                
                if finding.get("recommendation"):
                    lines.append(f"> 💡 {finding['recommendation']}")
                lines.append("")
    
    # Footer
    lines.append("---")
    lines.append("*Generated by [ShieldMyRepo](https://github.com/DhanushNehru/ShieldMyRepo)*")
    
    return "\n".join(lines)


def save_report(report_data: dict, output_dir: str, fmt: str = "json") -> str:
    """Save the report to a file.

    Args:
        report_data: Report dictionary from render_report.
        output_dir: Directory to save the report in.
        fmt: Output format ('json' or 'markdown').

    Returns:
        Path to the saved report file.
    """
    os.makedirs(output_dir, exist_ok=True)

    if fmt == "json":
        filepath = os.path.join(output_dir, "shieldmyrepo-report.json")
        with open(filepath, "w") as f:
            json.dump(report_data, f, indent=2)
        return filepath
    
    elif fmt == "markdown":
        filepath = os.path.join(output_dir, "shieldmyrepo-report.md")
        markdown_content = render_markdown(report_data)
        with open(filepath, "w") as f:
            f.write(markdown_content)
        return filepath

    return ""
