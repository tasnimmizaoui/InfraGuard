"""
Example usage scripts for InfraGuard.
Demonstrates how to use the library programmatically.
"""

# Example 1: Basic security check
def example_basic_check():
    """Run a basic security check."""
    from infra_guard.config import Config
    from infra_guard.detection_rules import SecurityChecker
    from infra_guard.utils import setup_logging
    
    # Setup
    setup_logging('INFO')
    config = Config()
    config.aws_region = 'us-east-1'
    
    # Run checks
    checker = SecurityChecker(config)
    findings = checker.run_all_checks()
    
    # Display results
    print(f"\nFound {len(findings)} security issues:")
    for finding in findings:
        print(f"  [{finding['severity']}] {finding['description']}")


# Example 2: Check only security groups
def example_security_groups():
    """Check only security groups for open ports."""
    from infra_guard.config import Config
    from infra_guard.detection_rules import SecurityChecker
    
    config = Config()
    config.risky_ports = [22, 3389, 3306, 5432]  # SSH, RDP, MySQL, PostgreSQL
    
    checker = SecurityChecker(config)
    findings = checker.check_security_groups()
    
    print(f"\nSecurity Group Findings: {len(findings)}")
    for finding in findings:
        print(f"\n{finding['description']}")
        print(f"Resource: {finding['resource']}")
        print(f"Recommendation: {finding['recommendation']}")


# Example 3: Analyze CloudTrail for root usage
def example_cloudtrail_analysis():
    """Analyze CloudTrail logs for root account usage."""
    from infra_guard.config import Config
    from infra_guard.log_ingestion import CloudTrailIngestion, CloudTrailAnalyzer
    
    config = Config()
    config.s3_bucket = 'your-logs-bucket'  # Replace with your bucket
    config.s3_cloudtrail_prefix = 'cloudtrail/'
    
    ingestion = CloudTrailIngestion(config)
    analyzer = CloudTrailAnalyzer()
    
    # Get last 24 hours of events
    events = ingestion.get_recent_events(hours=24, max_events=1000)
    print(f"Retrieved {len(events)} CloudTrail events")
    
    # Check for root usage
    root_usage = analyzer.find_root_account_usage(events)
    if root_usage:
        print(f"\n⚠️  WARNING: Root account used {len(root_usage)} times!")
        for event in root_usage:
            print(f"  - {event['event_name']} at {event['event_time']} from {event['source_ip']}")
    else:
        print("\n✅ No root account usage detected")
    
    # Check for failed auth
    failed_auth = analyzer.find_failed_auth_attempts(events)
    if failed_auth:
        print(f"\n⚠️  Found {len(failed_auth)} failed authentication attempts")


# Example 4: Analyze VPC Flow Logs
def example_vpc_flow_logs():
    """Analyze VPC Flow Logs for suspicious activity."""
    from infra_guard.config import Config
    from infra_guard.log_ingestion import VPCFlowLogIngestion
    
    config = Config()
    config.s3_bucket = 'your-logs-bucket'  # Replace with your bucket
    config.s3_vpc_flow_logs_prefix = 'vpc-flow-logs/'
    
    ingestion = VPCFlowLogIngestion(config)
    
    # Get recent flow logs
    records = ingestion.get_recent_flow_logs(hours=24, max_records=5000)
    print(f"Retrieved {len(records)} flow log records")
    
    # Analyze rejected traffic
    rejected = ingestion.filter_rejected_traffic(records)
    print(f"Rejected connections: {len(rejected)}")
    
    # Get top targeted ports
    top_ports = ingestion.get_top_rejected_ports(rejected, top_n=5)
    print("\nTop targeted ports:")
    for port_info in top_ports:
        print(f"  Port {port_info['port']}: {port_info['count']} attempts")
    
    # Get top source IPs
    top_ips = ingestion.get_top_source_ips(rejected, top_n=5)
    print("\nTop source IPs (potential attackers):")
    for ip_info in top_ips:
        print(f"  {ip_info['ip']}: {ip_info['count']} attempts")


# Example 5: Send alerts
def example_alerting():
    """Send alerts for findings."""
    from infra_guard.config import Config
    from infra_guard.detection_rules import SecurityChecker
    from infra_guard.alerting import AlertManager
    
    config = Config()
    config.slack_webhook_url = 'https://hooks.slack.com/services/YOUR/WEBHOOK'
    
    # Run checks
    checker = SecurityChecker(config)
    findings = checker.run_all_checks()
    
    # Send alerts
    alert_manager = AlertManager(config)
    results = alert_manager.send_alerts(findings)
    
    print(f"Alerts sent: {results['alerts_sent']}")
    print(f"Slack: {'✅' if results['slack_success'] else '❌'}")
    print(f"SNS: {'✅' if results['sns_success'] else '❌'}")


# Example 6: Custom finding creation
def example_custom_finding():
    """Create and save custom findings."""
    from infra_guard.utils import create_finding, save_findings_json
    
    findings = [
        create_finding(
            category="Custom",
            severity="HIGH",
            description="Example custom security finding",
            resource="arn:aws:ec2:us-east-1:123456789:instance/i-1234567890abcdef",
            details={"instance_type": "t2.micro", "public_ip": "1.2.3.4"},
            recommendation="Review and remediate this issue"
        )
    ]
    
    save_findings_json(findings, "custom_findings.json")
    print("Custom findings saved to custom_findings.json")


if __name__ == '__main__':
    print("InfraGuard Examples")
    print("=" * 60)
    print("\nUncomment the example you want to run:\n")
    
    # Uncomment one of these to run:
    # example_basic_check()
    # example_security_groups()
    # example_cloudtrail_analysis()
    # example_vpc_flow_logs()
    # example_alerting()
    # example_custom_finding()
    
    print("Edit examples.py to uncomment and run an example")
