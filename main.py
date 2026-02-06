#!/usr/bin/env python3
"""
InfraGuard CLI - Command-line interface for AWS security monitoring.
"""

import click
import sys
import logging
from datetime import datetime
from pathlib import Path

from infra_guard.config import Config
from infra_guard.utils import (
    setup_logging,
    save_findings_json,
    save_findings_csv,
    save_findings_log
)
from infra_guard.detection_rules import SecurityChecker
from infra_guard.plan_analyzer import TerraformPlanAnalyzer
from infra_guard.log_ingestion import CloudTrailIngestion, CloudTrailAnalyzer, VPCFlowLogIngestion
from infra_guard.alerting import AlertManager
from infra_guard.cli_utils import (
    console,
    print_banner,
    print_section,
    print_success,
    print_error,
    print_warning,
    print_info,
    print_summary,
    print_credentials_check,
    print_scan_progress,
    print_output_location,
    print_tips,
    create_findings_table,
    create_progress_bar
)


# Common options decorator
def common_options(func):
    """Decorator for common CLI options."""
    func = click.option('--region', default=None, help='AWS region (overrides AWS_REGION env var)')(func)
    func = click.option('--output-format', type=click.Choice(['json', 'csv', 'text']), default='json', help='Output format')(func)
    func = click.option('--output-file', type=click.Path(), default=None, help='Output file path')(func)
    func = click.option('--log-level', type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']), default='INFO', help='Logging level')(func)
    func = click.option('--no-banner', is_flag=True, help='Skip banner display')(func)
    return func


def run_security_checks(config: Config, checker: SecurityChecker, check_type: str, findings: list):
    """Run security checks with progress display."""
    print_section("Running Security Checks", "🔍")
    
    checks = []
    
    if check_type in ['all', 'iam']:
        if config.check_iam_unused_users:
            checks.append(('IAM Unused Users', lambda: checker.check_iam_unused_users()))
        if config.check_iam_root_usage:
            checks.append(('IAM Root Key Usage', lambda: checker.check_iam_root_key_exists()))
        if config.check_iam_overpermissive_policies:
            checks.append(('IAM Overpermissive Policies', lambda: checker.check_iam_overpermissive_policies()))
        checks.append(('IAM Password Policy', lambda: checker.check_iam_password_policy()))
    
    if check_type in ['all', 'network']:
        if config.check_security_groups:
            checks.append(('Security Groups', lambda: checker.check_security_groups()))
        if config.check_vpc_flow_logs_enabled:
            checks.append(('VPC Flow Logs', lambda: checker.check_vpc_flow_logs()))
        checks.append(('Public EC2 Instances', lambda: checker.check_ec2_public_instances()))
    
    if check_type in ['all', 's3']:
        checks.append(('S3 Bucket Security', lambda: checker.check_s3_public_buckets()))
        checks.append(('S3 Encryption', lambda: checker.check_s3_encryption()))
    
    if check_type in ['all', 'lambda']:
        checks.append(('Lambda Functions', lambda: checker.check_lambda_public_access()))
    
    # Run checks with progress
    for check_name, check_func in checks:
        print_scan_progress(check_name, "running")
        try:
            result = check_func()
            findings.extend(result)
            if result:
                print_scan_progress(check_name, "warning")
            else:
                print_scan_progress(check_name, "success")
        except Exception as e:
            logger = logging.getLogger("InfraGuard")
            logger.error(f"Error in {check_name}: {str(e)}")
            print_scan_progress(check_name, "error")


@click.group(invoke_without_command=True)
@click.option('--version', is_flag=True, help='Show version and exit')
@click.pass_context
def cli(ctx, version):
    """
    🔒 InfraGuard - AWS Cloud Security Monitoring with Shift-Left
    
    A comprehensive security scanning tool for AWS infrastructure.
    """
    if version:
        console.print("[bold cyan]InfraGuard[/bold cyan] version [bold]1.0.0[/bold]")
        ctx.exit()
    
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print("\n[yellow]No command specified. Use --help to see available commands.[/yellow]\n")
        console.print(ctx.get_help())


@cli.command()
@common_options
def check_all(region, output_format, output_file, log_level, no_banner):
    """Run all security checks on your AWS infrastructure."""
    if not no_banner:
        print_banner()
    
    # Setup
    config = create_config(region, output_format, output_file, log_level)
    setup_logging(config.log_level, config.log_format)
    logger = logging.getLogger("InfraGuard")
    
    # Validate credentials
    print_credentials_check(config.aws_region)
    
    try:
        # Run checks
        checker = SecurityChecker(config)
        findings = []
        
        run_security_checks(config, checker, 'all', findings)
        
        # Display results
        if findings:
            console.print()
            console.print(create_findings_table(findings))
        
        print_summary(findings, "All Infrastructure Checks")
        
        # Save findings
        save_output(findings, config)
        
        # Send alerts
        if config.sns_enabled or config.slack_enabled:
            print_section("Sending Alerts", "📢")
            alert_manager = AlertManager(config)
            alert_manager.send_alerts(findings)
            print_success("Alerts sent successfully")
        
        if not no_banner:
            print_tips()
        
        return 0
        
    except Exception as e:
        logger.error(f"Error during security check: {str(e)}", exc_info=True)
        print_error(f"Scan failed: {str(e)}")
        return 1


@cli.command()
@common_options
def check_iam(region, output_format, output_file, log_level, no_banner):
    """Run IAM security checks (users, policies, permissions)."""
    if not no_banner:
        print_banner()
    
    config = create_config(region, output_format, output_file, log_level)
    setup_logging(config.log_level, config.log_format)
    logger = logging.getLogger("InfraGuard")
    
    print_credentials_check(config.aws_region)
    
    try:
        checker = SecurityChecker(config)
        findings = []
        
        run_security_checks(config, checker, 'iam', findings)
        
        if findings:
            console.print()
            console.print(create_findings_table(findings))
        
        print_summary(findings, "IAM Security Checks")
        save_output(findings, config)
        
        return 0
        
    except Exception as e:
        logger.error(f"Error during IAM check: {str(e)}", exc_info=True)
        print_error(f"Scan failed: {str(e)}")
        return 1


@cli.command()
@common_options
def check_network(region, output_format, output_file, log_level, no_banner):
    """Run network security checks (Security Groups, VPCs, Flow Logs)."""
    if not no_banner:
        print_banner()
    
    config = create_config(region, output_format, output_file, log_level)
    setup_logging(config.log_level, config.log_format)
    logger = logging.getLogger("InfraGuard")
    
    print_credentials_check(config.aws_region)
    
    try:
        checker = SecurityChecker(config)
        findings = []
        
        run_security_checks(config, checker, 'network', findings)
        
        if findings:
            console.print()
            console.print(create_findings_table(findings))
        
        print_summary(findings, "Network Security Checks")
        save_output(findings, config)
        
        return 0
        
    except Exception as e:
        logger.error(f"Error during network check: {str(e)}", exc_info=True)
        print_error(f"Scan failed: {str(e)}")
        return 1


@cli.command()
@common_options
def check_s3(region, output_format, output_file, log_level, no_banner):
    """Run S3 bucket security checks (public access, encryption)."""
    if not no_banner:
        print_banner()
    
    config = create_config(region, output_format, output_file, log_level)
    setup_logging(config.log_level, config.log_format)
    logger = logging.getLogger("InfraGuard")
    
    print_credentials_check(config.aws_region)
    
    try:
        checker = SecurityChecker(config)
        findings = []
        
        run_security_checks(config, checker, 's3', findings)
        
        if findings:
            console.print()
            console.print(create_findings_table(findings))
        
        print_summary(findings, "S3 Security Checks")
        save_output(findings, config)
        
        return 0
        
    except Exception as e:
        logger.error(f"Error during S3 check: {str(e)}", exc_info=True)
        print_error(f"Scan failed: {str(e)}")
        return 1


@cli.command()
@common_options
def check_lambda(region, output_format, output_file, log_level, no_banner):
    """Run Lambda function security checks."""
    if not no_banner:
        print_banner()
    
    config = create_config(region, output_format, output_file, log_level)
    setup_logging(config.log_level, config.log_format)
    logger = logging.getLogger("InfraGuard")
    
    print_credentials_check(config.aws_region)
    
    try:
        checker = SecurityChecker(config)
        findings = []
        
        run_security_checks(config, checker, 'lambda', findings)
        
        if findings:
            console.print()
            console.print(create_findings_table(findings))
        
        print_summary(findings, "Lambda Security Checks")
        save_output(findings, config)
        
        return 0
        
    except Exception as e:
        logger.error(f"Error during Lambda check: {str(e)}", exc_info=True)
        print_error(f"Scan failed: {str(e)}")
        return 1


@cli.command(name='scan-plan')
@click.option('--plan-file', required=True, type=click.Path(exists=True), help='Path to Terraform plan JSON file')
@common_options
def scan_plan(plan_file, region, output_format, output_file, log_level, no_banner):
    """Scan Terraform plan for security issues (shift-left security)."""
    if not no_banner:
        print_banner()
    
    config = create_config(region, output_format, output_file, log_level)
    setup_logging(config.log_level, config.log_format)
    logger = logging.getLogger("InfraGuard")
    
    print_section("Terraform Plan Analysis", "📋")
    print_info(f"Analyzing plan file: {plan_file}")
    
    try:
        analyzer = TerraformPlanAnalyzer(config)
        findings = analyzer.analyze_plan_file(plan_file)
        
        if findings:
            console.print()
            console.print(create_findings_table(findings))
        
        print_summary(findings, "Terraform Plan Scan")
        save_output(findings, config)
        
        # Check for critical issues
        critical_findings = [f for f in findings if f.get('severity') == 'CRITICAL']
        high_findings = [f for f in findings if f.get('severity') == 'HIGH']
        
        if critical_findings:
            print_error(f"{len(critical_findings)} CRITICAL security issues found!")
            print_warning("⛔ Deployment should be BLOCKED until these issues are resolved.")
            return 1
        elif high_findings:
            print_warning(f"{len(high_findings)} HIGH severity issues found.")
            print_info("Review and remediate before deployment.")
            return 1
        
        print_success("No critical security issues found in Terraform plan")
        return 0
        
    except Exception as e:
        logger.error(f"Error scanning plan: {str(e)}", exc_info=True)
        print_error(f"Plan scan failed: {str(e)}")
        return 1


@cli.command()
@click.option('--hours', default=24, type=int, help='Hours of logs to analyze')
@common_options
def analyze_cloudtrail(hours, region, output_format, output_file, log_level, no_banner):
    """Analyze CloudTrail logs for suspicious activity."""
    if not no_banner:
        print_banner()
    
    config = create_config(region, output_format, output_file, log_level)
    setup_logging(config.log_level, config.log_format)
    logger = logging.getLogger("InfraGuard")
    
    print_section("CloudTrail Analysis", "📊")
    print_info(f"Analyzing last {hours} hours of CloudTrail logs")
    
    try:
        ingestion = CloudTrailIngestion(config)
        analyzer = CloudTrailAnalyzer(config)
        
        with create_progress_bar("Fetching CloudTrail events") as progress:
            task = progress.add_task("Loading...", total=100)
            events = ingestion.fetch_events(hours=hours)
            progress.update(task, completed=100)
        
        findings = analyzer.analyze_events(events)
        
        if findings:
            console.print()
            console.print(create_findings_table(findings))
        
        print_summary(findings, f"CloudTrail Analysis ({hours}h)")
        save_output(findings, config)
        
        return 0
        
    except Exception as e:
        logger.error(f"Error analyzing CloudTrail: {str(e)}", exc_info=True)
        print_error(f"Analysis failed: {str(e)}")
        return 1


@cli.command()
@click.option('--hours', default=24, type=int, help='Hours of logs to analyze')
@common_options
def analyze_vpc_logs(hours, region, output_format, output_file, log_level, no_banner):
    """Analyze VPC Flow Logs for network anomalies."""
    if not no_banner:
        print_banner()
    
    config = create_config(region, output_format, output_file, log_level)
    setup_logging(config.log_level, config.log_format)
    logger = logging.getLogger("InfraGuard")
    
    print_section("VPC Flow Logs Analysis", "🌐")
    print_info(f"Analyzing last {hours} hours of VPC Flow Logs")
    
    try:
        ingestion = VPCFlowLogIngestion(config)
        
        with create_progress_bar("Fetching VPC Flow Logs") as progress:
            task = progress.add_task("Loading...", total=100)
            events = ingestion.fetch_flow_logs(hours=hours)
            progress.update(task, completed=100)
        
        # Analyze for anomalies
        findings = ingestion.analyze_flow_logs(events)
        
        if findings:
            console.print()
            console.print(create_findings_table(findings))
        
        print_summary(findings, f"VPC Flow Logs Analysis ({hours}h)")
        save_output(findings, config)
        
        return 0
        
    except Exception as e:
        logger.error(f"Error analyzing VPC logs: {str(e)}", exc_info=True)
        print_error(f"Analysis failed: {str(e)}")
        return 1


def create_config(region, output_format, output_file, log_level):
    """Create configuration from CLI arguments."""
    config = Config()
    
    if region:
        config.aws_region = region
    if output_format:
        config.output_format = output_format
    if output_file:
        config.output_file = output_file
    if log_level:
        config.log_level = log_level
    
    return config


def save_output(findings, config):
    """Save findings to file."""
    if config.output_file:
        if config.output_format == 'json':
            save_findings_json(findings, config.output_file)
        elif config.output_format == 'csv':
            save_findings_csv(findings, config.output_file)
        elif config.output_format == 'text':
            save_findings_log(findings, config.output_file)
        
        print_output_location(config.output_file)
    else:
        # Auto-generate filename
        timestamp = datetime.now().strftime('%Y-%m-%d-%H%M%S')
        output_dir = Path('scan-results')
        output_dir.mkdir(exist_ok=True)
        
        filename = output_dir / f"infraguard-scan-{timestamp}.{config.output_format}"
        
        if config.output_format == 'json':
            save_findings_json(findings, str(filename))
        elif config.output_format == 'csv':
            save_findings_csv(findings, str(filename))
        elif config.output_format == 'text':
            save_findings_log(findings, str(filename))
        
        print_output_location(str(filename))


if __name__ == '__main__':
    try:
        sys.exit(cli())
    except KeyboardInterrupt:
        console.print("\n\n[yellow]⚠ Scan interrupted by user[/yellow]")
        sys.exit(130)
    except Exception as e:
        console.print(f"\n[red]✗ Unexpected error: {str(e)}[/red]")
        sys.exit(1)