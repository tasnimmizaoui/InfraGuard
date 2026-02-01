#!/usr/bin/env python3
"""
InfraGuard CLI - Command-line interface for AWS security monitoring.

Usage:
    python main.py check-all           # Run all security checks
    python main.py check-iam           # Run only IAM checks
    python main.py check-network       # Run only network-related checks
    python main.py analyze-cloudtrail  # Analyze CloudTrail logs
    python main.py analyze-vpc-logs    # Analyze VPC Flow Logs
    python main.py --help              # Show help
"""

import argparse
import sys
import logging
from datetime import datetime

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


def check_all(config: Config) -> int:
    """
    Run all security checks.
    
    Args:
        config: InfraGuard configuration
        
    Returns:
        Exit code (0 = success, 1 = error)
    """
    logger = logging.getLogger("InfraGuard")
    
    try:
        # Validate configuration
        warnings = config.validate()
        for warning in warnings:
            logger.warning(warning)
        
        # Run security checks
        checker = SecurityChecker(config)
        findings = checker.run_all_checks()
        
        # Save findings
        if config.output_format == 'json':
            save_findings_json(findings, config.output_file)
        elif config.output_format == 'csv':
            save_findings_csv(findings, config.output_file)
        elif config.output_format == 'log':
            save_findings_log(findings, config.output_file)
        
        # Send alerts if configured
        alert_manager = AlertManager(config)
        alert_results = alert_manager.send_alerts(findings)
        
        # Print summary
        summary = alert_manager.format_summary(findings)
        print(summary)
        
        logger.info(f"Security check completed. {len(findings)} findings.")
        return 0
    
    except Exception as e:
        logger.error(f"Error during security check: {str(e)}", exc_info=True)
        return 1


def check_iam(config: Config) -> int:
    """
    Run only IAM security checks.
    
    Args:
        config: InfraGuard configuration
        
    Returns:
        Exit code
    """
    logger = logging.getLogger("InfraGuard")
    
    try:
        checker = SecurityChecker(config)
        findings = []
        
        # Run only IAM checks
        if config.check_iam_unused_users:
            findings.extend(checker.check_iam_unused_users())
        
        if config.check_iam_root_usage:
            findings.extend(checker.check_iam_root_key_exists())
        
        if config.check_iam_overpermissive_policies:
            findings.extend(checker.check_iam_overpermissive_policies())
        
        findings.extend(checker.check_iam_password_policy())
        
        # Save and alert
        if config.output_format == 'json':
            save_findings_json(findings, config.output_file)
        elif config.output_format == 'csv':
            save_findings_csv(findings, config.output_file)
        
        alert_manager = AlertManager(config)
        print(alert_manager.format_summary(findings))
        
        return 0
    
    except Exception as e:
        logger.error(f"Error during IAM check: {str(e)}", exc_info=True)
        return 1


def check_network(config: Config) -> int:
    """
    Run only network-related security checks (Security Groups, VPC Flow Logs).
    
    Args:
        config: InfraGuard configuration
        
    Returns:
        Exit code
    """
    logger = logging.getLogger("InfraGuard")
    
    try:
        checker = SecurityChecker(config)
        findings = []
        
        # Run network checks
        if config.check_security_groups:
            findings.extend(checker.check_security_groups())
        
        if config.check_vpc_flow_logs_enabled:
            findings.extend(checker.check_vpc_flow_logs())
        
        findings.extend(checker.check_ec2_public_instances())
        
        # Save and alert
        if config.output_format == 'json':
            save_findings_json(findings, config.output_file)
        
        alert_manager = AlertManager(config)
        print(alert_manager.format_summary(findings))
        
        return 0
    
    except Exception as e:
        logger.error(f"Error during network check: {str(e)}", exc_info=True)
        return 1


def scan_plan(config: Config, plan_file: str) -> int:
    """
    Scan Terraform plan for security issues (shift-left security).
    
    Args:
        config: InfraGuard configuration
        plan_file: Path to Terraform plan JSON file
        
    Returns:
        Exit code (0 = no critical issues, 1 = critical issues found or error)
    """
    logger = logging.getLogger("InfraGuard")
    
    try:
        logger.info(f"Scanning Terraform plan: {plan_file}")
        
        # Analyze Terraform plan
        analyzer = TerraformPlanAnalyzer(config)
        findings = analyzer.analyze_plan_file(plan_file)
        
        # Save findings
        if config.output_format == 'json':
            save_findings_json(findings, config.output_file)
        elif config.output_format == 'csv':
            save_findings_csv(findings, config.output_file)
        elif config.output_format == 'log':
            save_findings_log(findings, config.output_file)
        
        # Format and display results
        alert_manager = AlertManager(config)
        summary = alert_manager.format_summary(findings)
        print(summary)
        
        # Check if any critical issues found
        critical_findings = [f for f in findings if f.get('severity') == 'CRITICAL']
        high_findings = [f for f in findings if f.get('severity') == 'HIGH']
        
        if critical_findings:
            logger.error(f"CRITICAL: {len(critical_findings)} critical security issues found in planned infrastructure!")
            logger.error("Deployment should be blocked until these issues are resolved.")
            return 1
        elif high_findings:
            logger.warning(f"WARNING: {len(high_findings)} high-severity security issues found in planned infrastructure.")
            logger.warning("Review these issues before proceeding with deployment.")
        
        logger.info(f"Plan scan completed. {len(findings)} total findings ({len(critical_findings)} critical, {len(high_findings)} high).")
        return 0 if not critical_findings else 1
    
    except Exception as e:
        logger.error(f"Error scanning Terraform plan: {str(e)}", exc_info=True)
        return 1


def analyze_cloudtrail(config: Config, hours: int = 24) -> int:
    """
    Analyze CloudTrail logs for security events.
    
    Args:
        config: InfraGuard configuration
        hours: Number of hours to analyze
        
    Returns:
        Exit code
    """
    logger = logging.getLogger("InfraGuard")
    
    try:
        ingestion = CloudTrailIngestion(config)
        analyzer = CloudTrailAnalyzer()
        
        logger.info(f"Analyzing CloudTrail logs from last {hours} hours...")
        
        # Get recent events
        events = ingestion.get_recent_events(hours=hours, max_events=5000)
        logger.info(f"Retrieved {len(events)} CloudTrail events")
        
        findings = []
        
        # Analyze for security patterns
        root_usage = analyzer.find_root_account_usage(events)
        if root_usage:
            for event in root_usage:
                findings.append({
                    "category": "CloudTrail",
                    "severity": "CRITICAL",
                    "description": f"Root account used for {event['event_name']}",
                    "resource": "Root Account",
                    "details": event,
                    "recommendation": "Use IAM users/roles instead of root account"
                })
        
        failed_auth = analyzer.find_failed_auth_attempts(events)
        if failed_auth:
            findings.append({
                "category": "CloudTrail",
                "severity": "MEDIUM",
                "description": f"Detected {len(failed_auth)} failed authentication attempts",
                "resource": "AWS Account",
                "details": {"failed_attempts": len(failed_auth), "sample": failed_auth[:5]},
                "recommendation": "Investigate source IPs and consider blocking if suspicious"
            })
        
        privilege_escalation = analyzer.find_privilege_escalation_attempts(events)
        if privilege_escalation:
            findings.append({
                "category": "CloudTrail",
                "severity": "HIGH",
                "description": f"Detected {len(privilege_escalation)} potential privilege escalation events",
                "resource": "AWS Account",
                "details": {"events": len(privilege_escalation), "sample": privilege_escalation[:5]},
                "recommendation": "Review IAM policy changes and ensure they are authorized"
            })
        
        # Save findings
        save_findings_json(findings, config.output_file)
        
        alert_manager = AlertManager(config)
        print(alert_manager.format_summary(findings))
        
        return 0
    
    except Exception as e:
        logger.error(f"Error analyzing CloudTrail: {str(e)}", exc_info=True)
        return 1


def analyze_vpc_logs(config: Config, hours: int = 24) -> int:
    """
    Analyze VPC Flow Logs for suspicious network activity.
    
    Args:
        config: InfraGuard configuration
        hours: Number of hours to analyze
        
    Returns:
        Exit code
    """
    logger = logging.getLogger("InfraGuard")
    
    try:
        ingestion = VPCFlowLogIngestion(config)
        
        logger.info(f"Analyzing VPC Flow Logs from last {hours} hours...")
        
        # Get recent flow logs
        records = ingestion.get_recent_flow_logs(hours=hours, max_records=10000)
        logger.info(f"Retrieved {len(records)} flow log records")
        
        findings = []
        
        # Analyze rejected traffic
        rejected = ingestion.filter_rejected_traffic(records)
        
        if rejected:
            top_ports = ingestion.get_top_rejected_ports(rejected, top_n=10)
            top_ips = ingestion.get_top_source_ips(rejected, top_n=10)
            
            findings.append({
                "category": "VPCFlowLogs",
                "severity": "INFO",
                "description": f"Detected {len(rejected)} rejected connection attempts",
                "resource": "VPC Flow Logs",
                "details": {
                    "rejected_count": len(rejected),
                    "top_targeted_ports": top_ports,
                    "top_source_ips": top_ips
                },
                "recommendation": "Review rejected traffic for port scanning or attack attempts"
            })
            
            # Alert on excessive port scanning
            if top_ports and top_ports[0]['count'] > 100:
                findings.append({
                    "category": "VPCFlowLogs",
                    "severity": "MEDIUM",
                    "description": f"Possible port scanning detected on port {top_ports[0]['port']} ({top_ports[0]['count']} attempts)",
                    "resource": "VPC",
                    "details": {"top_ports": top_ports[:5]},
                    "recommendation": "Verify traffic is expected or consider blocking source IPs"
                })
        
        # Save findings
        save_findings_json(findings, config.output_file)
        
        alert_manager = AlertManager(config)
        print(alert_manager.format_summary(findings))
        
        return 0
    
    except Exception as e:
        logger.error(f"Error analyzing VPC Flow Logs: {str(e)}", exc_info=True)
        return 1


def main():
    """
    Main CLI entry point.
    """
    parser = argparse.ArgumentParser(
        description="InfraGuard - AWS Cloud Security Monitoring Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py check-all                    # Run all security checks
  python main.py check-iam                    # Check only IAM
  python main.py check-network                # Check security groups and VPCs
  python main.py scan-plan --plan-file plan.json  # Scan Terraform plan (shift-left)
  python main.py analyze-cloudtrail --hours 48  # Analyze 48h of CloudTrail
  python main.py analyze-vpc-logs --hours 12    # Analyze 12h of VPC logs
  
Environment Variables:
  AWS_REGION              AWS region to monitor (default: us-east-1)
  INFRAGUARD_S3_BUCKET    S3 bucket for logs
  INFRAGUARD_SNS_TOPIC_ARN    SNS topic for alerts
  INFRAGUARD_SLACK_WEBHOOK    Slack webhook for alerts
  INFRAGUARD_LOG_LEVEL    Log level (DEBUG, INFO, WARNING, ERROR)
        """
    )
    
    parser.add_argument(
        'command',
        choices=['check-all', 'check-iam', 'check-network', 'scan-plan', 'analyze-cloudtrail', 'analyze-vpc-logs'],
        help='Command to execute'
    )
    
    parser.add_argument(
        '--region',
        default=None,
        help='AWS region (overrides AWS_REGION env var)'
    )
    
    parser.add_argument(
        '--plan-file',
        default=None,
        help='Path to Terraform plan JSON file for scan-plan command'
    )
    
    parser.add_argument(
        '--hours',
        type=int,
        default=24,
        help='Hours of logs to analyze (for log analysis commands)'
    )
    
    parser.add_argument(
        '--output-format',
        choices=['json', 'csv', 'log'],
        default='json',
        help='Output format for findings'
    )
    
    parser.add_argument(
        '--output-file',
        default=None,
        help='Output file path (default: stdout)'
    )
    
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Logging level'
    )
    
    args = parser.parse_args()
    
    # Create configuration
    config = Config()
    
    # Override with CLI arguments
    if args.region:
        config.aws_region = args.region
    if args.output_format:
        config.output_format = args.output_format
    if args.output_file:
        config.output_file = args.output_file
    if args.log_level:
        config.log_level = args.log_level
    
    # Setup logging
    setup_logging(config.log_level, config.log_format)
    logger = logging.getLogger("InfraGuard")
    
    logger.info(f"InfraGuard starting with command: {args.command}")
    logger.info(f"Configuration: {config}")
    
    # Execute command
    exit_code = 0
    
    if args.command == 'check-all':
        exit_code = check_all(config)
    elif args.command == 'check-iam':
        exit_code = check_iam(config)
    elif args.command == 'check-network':
        exit_code = check_network(config)
    elif args.command == 'scan-plan':
        if not args.plan_file:
            logger.error("--plan-file is required for scan-plan command")
            sys.exit(1)
        exit_code = scan_plan(config, args.plan_file)
    elif args.command == 'analyze-cloudtrail':
        exit_code = analyze_cloudtrail(config, args.hours)
    elif args.command == 'analyze-vpc-logs':
        exit_code = analyze_vpc_logs(config, args.hours)
    else:
        logger.error(f"Unknown command: {args.command}")
        exit_code = 1
    
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
