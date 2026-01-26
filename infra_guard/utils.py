"""
Utility functions for InfraGuard.
Provides helper functions for AWS operations, logging, and data processing.
"""

import json
import csv
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from pathlib import Path
import boto3
from botocore.exceptions import ClientError, BotoCoreError


def setup_logging(log_level: str = "INFO", log_format: Optional[str] = None) -> logging.Logger:
    """
    Configure logging for InfraGuard.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_format: Custom log format string
        
    Returns:
        Configured logger instance
    """
    if log_format is None:
        log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format=log_format,
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler("infraguard.log")
        ]
    )
    
    logger = logging.getLogger("InfraGuard")
    return logger


def get_aws_client(service_name: str, region: str = "us-east-1"):
    """
    Create and return an AWS boto3 client with error handling.
    
    Args:
        service_name: AWS service name (e.g., 'iam', 'ec2', 's3')
        region: AWS region name
        
    Returns:
        boto3 client instance
        
    Raises:
        BotoCoreError: If client creation fails
    """
    try:
        client = boto3.client(service_name, region_name=region)
        return client
    except Exception as e:
        logger = logging.getLogger("InfraGuard")
        logger.error(f"Failed to create AWS client for {service_name}: {str(e)}")
        raise


def get_aws_resource(service_name: str, region: str = "us-east-1"):
    """
    Create and return an AWS boto3 resource with error handling.
    
    Args:
        service_name: AWS service name (e.g., 'iam', 'ec2', 's3')
        region: AWS region name
        
    Returns:
        boto3 resource instance
        
    Raises:
        BotoCoreError: If resource creation fails
    """
    try:
        resource = boto3.resource(service_name, region_name=region)
        return resource
    except Exception as e:
        logger = logging.getLogger("InfraGuard")
        logger.error(f"Failed to create AWS resource for {service_name}: {str(e)}")
        raise


def is_date_older_than(date: datetime, days: int) -> bool:
    """
    Check if a datetime is older than specified number of days.
    
    Args:
        date: datetime to check
        days: Number of days threshold
        
    Returns:
        True if date is older than threshold, False otherwise
    """
    if date.tzinfo is None:
        # Make naive datetime timezone-aware (assume UTC)
        from datetime import timezone
        date = date.replace(tzinfo=timezone.utc)
    
    threshold = datetime.now(date.tzinfo) - timedelta(days=days)
    return date < threshold


def save_findings_json(findings: List[Dict[str, Any]], output_file: Optional[str] = None) -> None:
    """
    Save security findings to JSON format.
    
    Args:
        findings: List of finding dictionaries
        output_file: Output file path (if None, prints to stdout)
    """
    output = {
        "timestamp": datetime.utcnow().isoformat(),
        "total_findings": len(findings),
        "findings": findings
    }
    
    if output_file:
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2, default=str)
    else:
        print(json.dumps(output, indent=2, default=str))


def save_findings_csv(findings: List[Dict[str, Any]], output_file: Optional[str] = None) -> None:
    """
    Save security findings to CSV format.
    
    Args:
        findings: List of finding dictionaries
        output_file: Output file path (if None, prints to stdout)
    """
    if not findings:
        return
    
    # Extract all unique keys from findings
    fieldnames = set()
    for finding in findings:
        fieldnames.update(finding.keys())
    
    fieldnames = sorted(list(fieldnames))
    
    if output_file:
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(findings)
    else:
        import io
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(findings)
        print(output.getvalue())


def save_findings_log(findings: List[Dict[str, Any]], output_file: Optional[str] = None) -> None:
    """
    Save security findings in log format.
    
    Args:
        findings: List of finding dictionaries
        output_file: Output file path (if None, prints to stdout)
    """
    logger = logging.getLogger("InfraGuard.Findings")
    
    for finding in findings:
        severity = finding.get('severity', 'INFO').upper()
        message = f"[{finding.get('category', 'UNKNOWN')}] {finding.get('description', 'No description')}"
        
        if output_file:
            with open(output_file, 'a') as f:
                f.write(f"{datetime.utcnow().isoformat()} - {severity} - {message}\n")
                if 'resource' in finding:
                    f.write(f"  Resource: {finding['resource']}\n")
                if 'details' in finding:
                    f.write(f"  Details: {finding['details']}\n")
        else:
            if severity == 'CRITICAL' or severity == 'HIGH':
                logger.error(message)
            elif severity == 'MEDIUM':
                logger.warning(message)
            else:
                logger.info(message)


def handle_aws_error(error: Exception, context: str) -> Dict[str, Any]:
    """
    Handle AWS API errors and return structured error information.
    
    Args:
        error: The exception that was raised
        context: Context description for the error
        
    Returns:
        Dictionary with error details
    """
    logger = logging.getLogger("InfraGuard")
    
    error_info = {
        "context": context,
        "error_type": type(error).__name__,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    if isinstance(error, ClientError):
        error_code = error.response.get('Error', {}).get('Code', 'Unknown')
        error_message = error.response.get('Error', {}).get('Message', str(error))
        error_info["error_code"] = error_code
        error_info["error_message"] = error_message
        logger.error(f"{context}: AWS API Error [{error_code}] - {error_message}")
    else:
        error_info["error_message"] = str(error)
        logger.error(f"{context}: {str(error)}")
    
    return error_info


def paginate_aws_call(client, method_name: str, result_key: str, **kwargs) -> List[Dict[str, Any]]:
    """
    Handle pagination for AWS API calls that return paginated results.
    
    This is important for free-tier usage as it ensures we don't miss resources
    while efficiently fetching data.
    
    Args:
        client: boto3 client instance
        method_name: Name of the client method to call
        result_key: Key in response containing the results
        **kwargs: Additional arguments to pass to the method
        
    Returns:
        List of all results from paginated responses
        
    Example:
        instances = paginate_aws_call(ec2_client, 'describe_instances', 'Reservations')
    """
    results = []
    paginator = client.get_paginator(method_name)
    
    try:
        for page in paginator.paginate(**kwargs):
            if result_key in page:
                results.extend(page[result_key])
    except Exception as e:
        handle_aws_error(e, f"Pagination for {method_name}")
    
    return results


def get_account_id() -> Optional[str]:
    """
    Get the current AWS account ID.
    
    Returns:
        AWS account ID or None if unable to retrieve
    """
    try:
        sts_client = boto3.client('sts')
        response = sts_client.get_caller_identity()
        return response['Account']
    except Exception as e:
        handle_aws_error(e, "Getting AWS account ID")
        return None


def create_finding(
    category: str,
    severity: str,
    description: str,
    resource: str,
    details: Optional[Dict[str, Any]] = None,
    recommendation: Optional[str] = None
) -> Dict[str, Any]:
    """
    Create a standardized security finding dictionary.
    
    Args:
        category: Finding category (IAM, SecurityGroup, S3, etc.)
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        description: Human-readable description of the finding
        resource: AWS resource identifier (ARN, ID, name, etc.)
        details: Additional details about the finding
        recommendation: Suggested remediation action
        
    Returns:
        Standardized finding dictionary
    """
    finding = {
        "timestamp": datetime.utcnow().isoformat(),
        "category": category,
        "severity": severity,
        "description": description,
        "resource": resource,
    }
    
    if details:
        finding["details"] = details
    
    if recommendation:
        finding["recommendation"] = recommendation
    
    return finding


def chunk_list(items: List[Any], chunk_size: int) -> List[List[Any]]:
    """
    Split a list into chunks of specified size.
    Useful for batch API calls that have size limits.
    
    Args:
        items: List to chunk
        chunk_size: Maximum size of each chunk
        
    Returns:
        List of chunked lists
    """
    return [items[i:i + chunk_size] for i in range(0, len(items), chunk_size)]
