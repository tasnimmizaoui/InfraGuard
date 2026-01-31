"""
Configuration module for InfraGuard.
Manages AWS region, S3 bucket, SNS topic, and other settings.
"""

import os
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class Config:
    """
    Configuration class for InfraGuard AWS monitoring.
    
    Environment variables can override default values:
    - AWS_REGION: AWS region to monitor (default: us-east-1)
    - INFRAGUARD_S3_BUCKET: S3 bucket for CloudTrail/VPC Flow Logs
    - INFRAGUARD_SNS_TOPIC_ARN: SNS topic ARN for alerts
    - INFRAGUARD_SLACK_WEBHOOK: Slack webhook URL for alerts
    - INFRAGUARD_LOG_LEVEL: Logging level (DEBUG, INFO, WARNING, ERROR)
    """
    
    # AWS Configuration
    aws_region: str = field(default_factory=lambda: os.getenv("AWS_REGION", "us-east-1").strip())
    
    # S3 Configuration (for CloudTrail and VPC Flow Logs)
    s3_bucket: Optional[str] = field(default_factory=lambda: os.getenv("INFRAGUARD_S3_BUCKET", "").strip() or None)
    s3_cloudtrail_prefix: str = "cloudtrail/"
    s3_vpc_flow_logs_prefix: str = "vpc-flow-logs/"
    
    # SNS Configuration (for alerts)
    sns_topic_arn: Optional[str] = field(default_factory=lambda: os.getenv("INFRAGUARD_SNS_TOPIC_ARN", "").strip() or None)
    
    # Slack Configuration (alternative to SNS)
    slack_webhook_url: Optional[str] = field(default_factory=lambda: os.getenv("INFRAGUARD_SLACK_WEBHOOK"))
    
    # Logging Configuration
    log_level: str = field(default_factory=lambda: os.getenv("INFRAGUARD_LOG_LEVEL", "INFO"))
    log_format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    # Detection Rules Configuration
    # IAM checks
    check_iam_unused_users: bool = True
    check_iam_root_usage: bool = True
    check_iam_overpermissive_policies: bool = True
    iam_unused_threshold_days: int = 90  # Days before user is considered unused
    
    # Security Group checks
    check_security_groups: bool = True
    risky_ports: list[int] = field(default_factory=lambda: [22, 3389, 3306, 5432, 27017, 6379])
    
    # S3 bucket checks
    check_s3_public_access: bool = True
    check_s3_encryption: bool = True
    check_s3_versioning: bool = True
    check_s3_bucket_policy: bool = True
    
    # CloudTrail checks
    check_cloudtrail_enabled: bool = True
    
    # VPC Flow Logs checks
    check_vpc_flow_logs_enabled: bool = True
    
    # ECS/EKS checks (optional, can be expensive)
    check_ecs_containers: bool = False
    check_eks_clusters: bool = False
    
    # Output Configuration
    output_format: str = "json"  # Options: json, csv, log
    output_file: Optional[str] = None  # If None, prints to stdout
    
    def validate(self) -> list[str]:
        """
        Validate configuration and return list of warnings/errors.
        
        Returns:
            List of validation messages (empty if all valid)
        """
        warnings = []
        
        if not self.s3_bucket:
            warnings.append("S3_BUCKET not set - CloudTrail and VPC Flow Log ingestion will be disabled")
        
        if not self.sns_topic_arn and not self.slack_webhook_url:
            warnings.append("Neither SNS_TOPIC_ARN nor SLACK_WEBHOOK set - alerts will only be logged locally")
        
        if self.output_format not in ["json", "csv", "log"]:
            warnings.append(f"Invalid output_format: {self.output_format}. Using 'json' instead.")
            self.output_format = "json"
        
        return warnings
    
    def __str__(self) -> str:
        """String representation masking sensitive data."""
        return (
            f"Config(region={self.aws_region}, "
            f"s3_bucket={self.s3_bucket}, "
            f"sns_enabled={bool(self.sns_topic_arn)}, "
            f"slack_enabled={bool(self.slack_webhook_url)})"
        )
