"""
InfraGuard - AWS Cloud Security Monitoring Tool (Free Tier Friendly)

A lightweight Python-based security monitoring tool for AWS infrastructure
that focuses on detecting common security misconfigurations while staying
within AWS free tier limits.
"""

__version__ = "0.1.0"
__author__ = "InfraGuard Team"

from .config import Config
from .log_ingestion import CloudTrailIngestion, VPCFlowLogIngestion
from .detection_rules import SecurityChecker
from .alerting import AlertManager

__all__ = [
    "Config",
    "CloudTrailIngestion",
    "VPCFlowLogIngestion",
    "SecurityChecker",
    "AlertManager",
]
