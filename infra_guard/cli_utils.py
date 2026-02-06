"""
CLI utilities for InfraGuard - Beautiful terminal output.
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.text import Text
from rich import box
from datetime import datetime
from typing import List, Dict

console = Console()


def print_banner():
    """Display InfraGuard banner."""
    banner = """
[bold cyan]
  ___        __           ____                     _ 
 |_ _|_ __  / _|_ __ __ _/ ___|_   _  __ _ _ __ __| |
  | || '_ \| |_| '__/ _` | |  _| | | |/ _` | '__/ _` |
  | || | | |  _| | | (_| | |_| | |_| | (_| | | | (_| |
 |___|_| |_|_| |_|  \__,_|\____|\__,_|\__,_|_|  \__,_|
[/bold cyan]
[bold white]AWS Cloud Security Monitoring with Shift-Left[/bold white]
[dim]Version 1.0.0 | Built By HungryHeidi for Security[/dim]
    """
    console.print(Panel(banner, border_style="cyan", box=box.ROUNDED))


def print_section(title: str, emoji: str = "📋"):
    """Print a section header."""
    console.print(f"\n{emoji} [bold cyan]{title}[/bold cyan]")
    console.print("━" * 60, style="cyan")


def print_success(message: str):
    """Print success message."""
    console.print(f"✓ [green]{message}[/green]")


def print_error(message: str):
    """Print error message."""
    console.print(f"✗ [red]{message}[/red]")


def print_warning(message: str):
    """Print warning message."""
    console.print(f"⚠ [yellow]{message}[/yellow]")


def print_info(message: str):
    """Print info message."""
    console.print(f"ℹ [blue]{message}[/blue]")


def create_findings_table(findings: List[Dict]) -> Table:
    """
    Create a rich table for displaying findings.
    
    Args:
        findings: List of security findings
        
    Returns:
        Rich Table object
    """
    # Count by severity
    severity_counts = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0,
        'INFO': 0
    }
    
    for finding in findings:
        severity = finding.get('severity', 'INFO')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    # Create table
    table = Table(title="Security Findings", box=box.ROUNDED, show_header=True, header_style="bold cyan")
    table.add_column("Severity", style="bold", width=12)
    table.add_column("Resource", style="cyan", width=30)
    table.add_column("Issue", width=50)
    table.add_column("Location", style="dim", width=20)
    
    # Sort findings by severity
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
    sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get('severity', 'INFO'), 99))
    
    for finding in sorted_findings:
        severity = finding.get('severity', 'INFO')
        resource_type = finding.get('resource_type', 'Unknown')
        resource_id = finding.get('resource_id', 'N/A')
        issue = finding.get('issue', 'No description')
        region = finding.get('region', 'global')
        
        # Color code severity
        if severity == 'CRITICAL':
            severity_text = f"[red bold]🔴 {severity}[/red bold]"
        elif severity == 'HIGH':
            severity_text = f"[red]🟠 {severity}[/red]"
        elif severity == 'MEDIUM':
            severity_text = f"[yellow]🟡 {severity}[/yellow]"
        elif severity == 'LOW':
            severity_text = f"[blue]🔵 {severity}[/blue]"
        else:
            severity_text = f"[dim]⚪ {severity}[/dim]"
        
        table.add_row(
            severity_text,
            f"{resource_type}\n[dim]{resource_id[:40]}[/dim]",
            issue,
            region
        )
    
    return table


def print_summary(findings: List[Dict], scan_type: str = "all"):
    """
    Print scan summary with findings breakdown.
    
    Args:
        findings: List of security findings
        scan_type: Type of scan performed
    """
    # Count by severity
    severity_counts = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0,
        'INFO': 0
    }
    
    for finding in findings:
        severity = finding.get('severity', 'INFO')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    # Create summary panel
    summary_text = f"""
[bold]Scan Type:[/bold] {scan_type}
[bold]Timestamp:[/bold] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
[bold]Total Findings:[/bold] {len(findings)}

[bold]Severity Breakdown:[/bold]
  🔴 CRITICAL: {severity_counts['CRITICAL']}
  🟠 HIGH:     {severity_counts['HIGH']}
  🟡 MEDIUM:   {severity_counts['MEDIUM']}
  🔵 LOW:      {severity_counts['LOW']}
  ⚪ INFO:     {severity_counts['INFO']}
    """
    
    # Determine panel color based on severity
    if severity_counts['CRITICAL'] > 0:
        border_style = "red"
        title = "🚨 CRITICAL Issues Found"
    elif severity_counts['HIGH'] > 0:
        border_style = "yellow"
        title = "⚠️  Security Issues Detected"
    else:
        border_style = "green"
        title = "✅ Scan Complete"
    
    console.print(Panel(summary_text.strip(), title=title, border_style=border_style, box=box.ROUNDED))


def create_progress_bar(description: str = "Processing"):
    """
    Create a progress bar context manager.
    
    Args:
        description: Description text for the progress bar
        
    Returns:
        Progress context manager
    """
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    )


def print_credentials_check(region: str, has_credentials: bool = True):
    """Print credentials validation status."""
    print_section("Environment Check", "🔐")
    
    if has_credentials:
        print_success(f"AWS credentials validated")
        print_success(f"Region: {region}")
    else:
        print_error("AWS credentials not found")
        console.print("\n[yellow]Please configure AWS credentials:[/yellow]")
        console.print("  1. Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY")
        console.print("  2. AWS credentials file: ~/.aws/credentials")
        console.print("  3. IAM role (when running on EC2/Lambda)")


def print_scan_progress(check_name: str, status: str = "running"):
    """
    Print scan progress for a specific check.
    
    Args:
        check_name: Name of the check
        status: Status (running, success, warning, error)
    """
    if status == "running":
        console.print(f"  ⏳ [cyan]{check_name}[/cyan]", end="")
    elif status == "success":
        console.print(f"\r  ✓ [green]{check_name}[/green]")
    elif status == "warning":
        console.print(f"\r  ⚠ [yellow]{check_name}[/yellow]")
    elif status == "error":
        console.print(f"\r  ✗ [red]{check_name}[/red]")


def print_output_location(filepath: str):
    """Print output file location."""
    console.print(f"\n💾 [bold]Results saved to:[/bold] [cyan]{filepath}[/cyan]")


def print_tips():
    """Print helpful tips."""
    tips = [
        "Use [cyan]--interactive[/cyan] for guided scanning",
        "Add [cyan]--severity HIGH[/cyan] to filter critical issues only",
        "Run [cyan]scan-plan[/cyan] before deployment for shift-left security",
        "Check [cyan]--help[/cyan] for all available options"
    ]
    
    console.print(f"\n💡 [bold]Tips:[/bold]")
    for tip in tips:
        console.print(f"  • {tip}")
