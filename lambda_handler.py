"""
AWS Lambda handler for InfraGuard.
Allows running InfraGuard as a scheduled Lambda function.

Deploy this to AWS Lambda and trigger it with CloudWatch Events/EventBridge
for automated security scanning.
"""

import json
import logging
from infra_guard.config import Config
from infra_guard.detection_rules import SecurityChecker
from infra_guard.alerting import AlertManager


def handler(event, context):
    """
    Lambda handler function for InfraGuard security checks.
    
    Args:
        event: Lambda event object (can contain custom configuration)
        context: Lambda context object
        
    Returns:
        Dictionary with execution results
    """
    # Setup logging for Lambda
    logger = logging.getLogger("InfraGuard")
    logger.setLevel(logging.INFO)
    
    try:
        # Create configuration
        # Lambda will use environment variables or IAM role credentials
        config = Config()
        
        # Override with event parameters if provided
        if 'aws_region' in event:
            config.aws_region = event['aws_region']
        
        logger.info(f"Starting InfraGuard security check in {config.aws_region}")
        
        # Validate configuration
        warnings = config.validate()
        for warning in warnings:
            logger.warning(warning)
        
        # Run security checks
        checker = SecurityChecker(config)
        findings = checker.run_all_checks()
        
        logger.info(f"Security check completed. Found {len(findings)} issues.")
        
        # Send alerts if configured
        alert_manager = AlertManager(config)
        alert_results = alert_manager.send_alerts(findings)
        
        # Return results
        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'InfraGuard scan completed successfully',
                'total_findings': len(findings),
                'findings_by_severity': {
                    'CRITICAL': len([f for f in findings if f.get('severity') == 'CRITICAL']),
                    'HIGH': len([f for f in findings if f.get('severity') == 'HIGH']),
                    'MEDIUM': len([f for f in findings if f.get('severity') == 'MEDIUM']),
                    'LOW': len([f for f in findings if f.get('severity') == 'LOW']),
                },
                'alerts_sent': alert_results.get('alerts_sent', 0),
                'execution_time_ms': context.get_remaining_time_in_millis() if context else 0
            }, default=str)
        }
    
    except Exception as e:
        logger.error(f"Error during Lambda execution: {str(e)}", exc_info=True)
        
        return {
            'statusCode': 500,
            'body': json.dumps({
                'message': 'InfraGuard scan failed',
                'error': str(e)
            })
        }


# For local testing
if __name__ == '__main__':
    # Simulate Lambda event and context
    test_event = {}
    test_context = type('Context', (), {'get_remaining_time_in_millis': lambda: 300000})()
    
    result = handler(test_event, test_context)
    print(json.dumps(result, indent=2))
