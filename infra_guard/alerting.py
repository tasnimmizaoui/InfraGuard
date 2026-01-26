"""
Alerting module for InfraGuard.
Handles sending alerts via SNS and Slack when security issues are detected.
"""

import json
import logging
from typing import List, Dict, Any, Optional
import boto3
import urllib.request
from botocore.exceptions import ClientError

from .utils import get_aws_client, handle_aws_error
from .config import Config


class AlertManager:
    """
    Manage alert delivery via SNS and/or Slack.
    
    SNS (Simple Notification Service) is free tier eligible:
    - First 1,000 notifications per month are free
    - Additional notifications are very cheap ($0.50 per million)
    
    Slack webhooks are free and unlimited.
    """
    
    def __init__(self, config: Config):
        """
        Initialize alert manager.
        
        Args:
            config: InfraGuard configuration object
        """
        self.config = config
        self.logger = logging.getLogger("InfraGuard.Alerting")
        
        # Initialize SNS client if configured
        self.sns_client = None
        if config.sns_topic_arn:
            self.sns_client = get_aws_client('sns', config.aws_region)
    
    def send_alerts(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Send alerts for security findings.
        
        Args:
            findings: List of security findings to alert on
            
        Returns:
            Dictionary with alert delivery results
        """
        if not findings:
            self.logger.info("No findings to alert on")
            return {"status": "no_findings", "alerts_sent": 0}
        
        results = {
            "total_findings": len(findings),
            "alerts_sent": 0,
            "sns_success": False,
            "slack_success": False,
            "errors": []
        }
        
        # Filter by severity (only alert on MEDIUM and above)
        alert_worthy = [
            f for f in findings 
            if f.get('severity') in ['CRITICAL', 'HIGH', 'MEDIUM']
        ]
        
        if not alert_worthy:
            self.logger.info("No high-severity findings to alert on")
            return results
        
        # Send to SNS
        if self.config.sns_topic_arn:
            sns_result = self.send_sns_alert(alert_worthy)
            results["sns_success"] = sns_result["success"]
            if sns_result["success"]:
                results["alerts_sent"] += 1
            else:
                results["errors"].append(sns_result.get("error"))
        
        # Send to Slack
        if self.config.slack_webhook_url:
            slack_result = self.send_slack_alert(alert_worthy)
            results["slack_success"] = slack_result["success"]
            if slack_result["success"]:
                results["alerts_sent"] += 1
            else:
                results["errors"].append(slack_result.get("error"))
        
        return results
    
    def send_sns_alert(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Send alert via AWS SNS.
        
        Args:
            findings: List of security findings
            
        Returns:
            Dictionary with success status and message ID
        """
        if not self.sns_client or not self.config.sns_topic_arn:
            return {"success": False, "error": "SNS not configured"}
        
        try:
            # Create alert message
            severity_counts = {}
            for finding in findings:
                severity = finding.get('severity', 'UNKNOWN')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            subject = f"InfraGuard Alert: {len(findings)} Security Issues Detected"
            
            # Create message body
            message_lines = [
                "InfraGuard Security Alert",
                "=" * 50,
                f"Total Findings: {len(findings)}",
                "",
                "Severity Breakdown:"
            ]
            
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if severity in severity_counts:
                    message_lines.append(f"  {severity}: {severity_counts[severity]}")
            
            message_lines.append("")
            message_lines.append("Top Findings:")
            message_lines.append("")
            
            # Add top 10 findings
            for i, finding in enumerate(findings[:10], 1):
                message_lines.append(
                    f"{i}. [{finding.get('severity')}] {finding.get('description')}"
                )
                message_lines.append(f"   Resource: {finding.get('resource')}")
                if finding.get('recommendation'):
                    message_lines.append(f"   Recommendation: {finding.get('recommendation')}")
                message_lines.append("")
            
            if len(findings) > 10:
                message_lines.append(f"... and {len(findings) - 10} more findings")
            
            message = "\n".join(message_lines)
            
            # Send to SNS
            response = self.sns_client.publish(
                TopicArn=self.config.sns_topic_arn,
                Subject=subject[:100],  # SNS subject max 100 chars
                Message=message
            )
            
            message_id = response.get('MessageId')
            self.logger.info(f"SNS alert sent successfully. Message ID: {message_id}")
            
            return {"success": True, "message_id": message_id}
        
        except Exception as e:
            error_info = handle_aws_error(e, "Sending SNS alert")
            return {"success": False, "error": str(error_info)}
    
    def send_slack_alert(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Send alert via Slack webhook.
        
        Args:
            findings: List of security findings
            
        Returns:
            Dictionary with success status
        """
        if not self.config.slack_webhook_url:
            return {"success": False, "error": "Slack webhook not configured"}
        
        try:
            # Count findings by severity
            severity_counts = {}
            for finding in findings:
                severity = finding.get('severity', 'UNKNOWN')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Build Slack message using Block Kit
            blocks = [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"🔒 InfraGuard Security Alert: {len(findings)} Issues Detected"
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Total Findings:*\n{len(findings)}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Critical:* {severity_counts.get('CRITICAL', 0)}\n*High:* {severity_counts.get('HIGH', 0)}\n*Medium:* {severity_counts.get('MEDIUM', 0)}"
                        }
                    ]
                },
                {
                    "type": "divider"
                }
            ]
            
            # Add top findings
            for i, finding in enumerate(findings[:5], 1):
                severity = finding.get('severity', 'UNKNOWN')
                
                # Emoji based on severity
                emoji_map = {
                    'CRITICAL': '🔴',
                    'HIGH': '🟠',
                    'MEDIUM': '🟡',
                    'LOW': '🔵',
                    'INFO': '⚪'
                }
                emoji = emoji_map.get(severity, '⚫')
                
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"{emoji} *{severity}*: {finding.get('description')}\n"
                                f"_Resource:_ `{finding.get('resource')}`\n"
                                f"_Recommendation:_ {finding.get('recommendation', 'Review and remediate')}"
                    }
                })
            
            if len(findings) > 5:
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"_... and {len(findings) - 5} more findings_"
                    }
                })
            
            # Prepare webhook payload
            payload = {
                "blocks": blocks,
                "text": f"InfraGuard Alert: {len(findings)} security issues detected"
            }
            
            # Send to Slack
            req = urllib.request.Request(
                self.config.slack_webhook_url,
                data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json'}
            )
            
            with urllib.request.urlopen(req) as response:
                response_data = response.read().decode('utf-8')
                
                if response.status == 200:
                    self.logger.info("Slack alert sent successfully")
                    return {"success": True}
                else:
                    self.logger.error(f"Slack alert failed: {response_data}")
                    return {"success": False, "error": response_data}
        
        except Exception as e:
            self.logger.error(f"Failed to send Slack alert: {str(e)}")
            return {"success": False, "error": str(e)}
    
    def format_summary(self, findings: List[Dict[str, Any]]) -> str:
        """
        Create a formatted summary of findings for logging/display.
        
        Args:
            findings: List of security findings
            
        Returns:
            Formatted summary string
        """
        if not findings:
            return "No security findings detected."
        
        severity_counts = {}
        category_counts = {}
        
        for finding in findings:
            severity = finding.get('severity', 'UNKNOWN')
            category = finding.get('category', 'UNKNOWN')
            
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            category_counts[category] = category_counts.get(category, 0) + 1
        
        lines = [
            "",
            "=" * 60,
            "InfraGuard Security Summary",
            "=" * 60,
            f"Total Findings: {len(findings)}",
            "",
            "By Severity:",
        ]
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if severity in severity_counts:
                lines.append(f"  {severity}: {severity_counts[severity]}")
        
        lines.append("")
        lines.append("By Category:")
        
        for category, count in sorted(category_counts.items()):
            lines.append(f"  {category}: {count}")
        
        lines.append("=" * 60)
        
        return "\n".join(lines)
