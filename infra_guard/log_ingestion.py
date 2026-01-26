"""
Log ingestion module for CloudTrail and VPC Flow Logs.
Reads and parses logs from S3 for security analysis.
"""

import json
import gzip
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Iterator
import boto3
from botocore.exceptions import ClientError

from .utils import handle_aws_error, get_aws_client
from .config import Config


class CloudTrailIngestion:
    """
    Ingest and parse CloudTrail logs from S3.
    
    CloudTrail provides audit logs of API calls made in your AWS account.
    This is crucial for detecting unauthorized access, privilege escalation,
    and suspicious API usage patterns.
    
    Free Tier Note: CloudTrail itself is free for one trail. S3 storage costs
    apply but are minimal for log files.
    """
    
    def __init__(self, config: Config):
        """
        Initialize CloudTrail ingestion.
        
        Args:
            config: InfraGuard configuration object
        """
        self.config = config
        self.logger = logging.getLogger("InfraGuard.CloudTrail")
        self.s3_client = get_aws_client('s3', config.aws_region)
    
    def list_log_files(
        self, 
        start_time: Optional[datetime] = None, 
        end_time: Optional[datetime] = None,
        max_files: int = 100
    ) -> List[str]:
        """
        List CloudTrail log files in S3 within a time range.
        
        Args:
            start_time: Start of time range (default: 24 hours ago)
            end_time: End of time range (default: now)
            max_files: Maximum number of files to return (cost control)
            
        Returns:
            List of S3 keys for CloudTrail log files
        """
        if not self.config.s3_bucket:
            self.logger.warning("S3 bucket not configured for CloudTrail")
            return []
        
        if start_time is None:
            start_time = datetime.utcnow() - timedelta(hours=24)
        if end_time is None:
            end_time = datetime.utcnow()
        
        log_files = []
        
        try:
            paginator = self.s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(
                Bucket=self.config.s3_bucket,
                Prefix=self.config.s3_cloudtrail_prefix
            )
            
            for page in pages:
                if 'Contents' not in page:
                    continue
                
                for obj in page['Contents']:
                    # Filter by time if needed
                    if start_time <= obj['LastModified'].replace(tzinfo=None) <= end_time:
                        log_files.append(obj['Key'])
                    
                    if len(log_files) >= max_files:
                        self.logger.warning(f"Reached max_files limit ({max_files})")
                        return log_files
            
            self.logger.info(f"Found {len(log_files)} CloudTrail log files")
            return log_files
            
        except ClientError as e:
            handle_aws_error(e, "Listing CloudTrail log files")
            return []
    
    def parse_log_file(self, s3_key: str) -> List[Dict[str, Any]]:
        """
        Download and parse a CloudTrail log file from S3.
        
        Args:
            s3_key: S3 key of the CloudTrail log file
            
        Returns:
            List of CloudTrail event records
        """
        events = []
        
        try:
            # Download the log file
            response = self.s3_client.get_object(
                Bucket=self.config.s3_bucket,
                Key=s3_key
            )
            
            # CloudTrail logs are gzipped JSON
            if s3_key.endswith('.gz'):
                with gzip.GzipFile(fileobj=response['Body']) as gzipfile:
                    content = gzipfile.read()
            else:
                content = response['Body'].read()
            
            # Parse JSON
            log_data = json.loads(content)
            
            # CloudTrail wraps events in a 'Records' key
            if 'Records' in log_data:
                events = log_data['Records']
            
            self.logger.debug(f"Parsed {len(events)} events from {s3_key}")
            return events
            
        except Exception as e:
            handle_aws_error(e, f"Parsing CloudTrail log file {s3_key}")
            return []
    
    def get_recent_events(
        self, 
        hours: int = 24,
        event_names: Optional[List[str]] = None,
        max_events: int = 1000
    ) -> List[Dict[str, Any]]:
        """
        Get recent CloudTrail events, optionally filtered by event name.
        
        Args:
            hours: Number of hours back to look
            event_names: List of CloudTrail event names to filter (e.g., ['ConsoleLogin', 'AssumeRole'])
            max_events: Maximum events to return (cost control)
            
        Returns:
            List of CloudTrail events
        """
        start_time = datetime.utcnow() - timedelta(hours=hours)
        end_time = datetime.utcnow()
        
        log_files = self.list_log_files(start_time, end_time, max_files=50)
        
        all_events = []
        for log_file in log_files:
            events = self.parse_log_file(log_file)
            
            # Filter by event names if specified
            if event_names:
                events = [e for e in events if e.get('eventName') in event_names]
            
            all_events.extend(events)
            
            if len(all_events) >= max_events:
                self.logger.warning(f"Reached max_events limit ({max_events})")
                break
        
        return all_events[:max_events]


class VPCFlowLogIngestion:
    """
    Ingest and parse VPC Flow Logs from S3.
    
    VPC Flow Logs capture network traffic metadata for your VPCs.
    Useful for detecting port scanning, unusual traffic patterns, and
    unauthorized network access attempts.
    
    Free Tier Note: VPC Flow Logs to S3 have minimal costs. CloudWatch Logs
    are more expensive, so we focus on S3-based logs.
    """
    
    def __init__(self, config: Config):
        """
        Initialize VPC Flow Log ingestion.
        
        Args:
            config: InfraGuard configuration object
        """
        self.config = config
        self.logger = logging.getLogger("InfraGuard.VPCFlowLogs")
        self.s3_client = get_aws_client('s3', config.aws_region)
    
    def list_log_files(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        max_files: int = 50
    ) -> List[str]:
        """
        List VPC Flow Log files in S3 within a time range.
        
        Args:
            start_time: Start of time range (default: 24 hours ago)
            end_time: End of time range (default: now)
            max_files: Maximum number of files to return
            
        Returns:
            List of S3 keys for VPC Flow Log files
        """
        if not self.config.s3_bucket:
            self.logger.warning("S3 bucket not configured for VPC Flow Logs")
            return []
        
        if start_time is None:
            start_time = datetime.utcnow() - timedelta(hours=24)
        if end_time is None:
            end_time = datetime.utcnow()
        
        log_files = []
        
        try:
            paginator = self.s3_client.get_paginator('list_objects_v2')
            pages = paginator.paginate(
                Bucket=self.config.s3_bucket,
                Prefix=self.config.s3_vpc_flow_logs_prefix
            )
            
            for page in pages:
                if 'Contents' not in page:
                    continue
                
                for obj in page['Contents']:
                    if start_time <= obj['LastModified'].replace(tzinfo=None) <= end_time:
                        log_files.append(obj['Key'])
                    
                    if len(log_files) >= max_files:
                        return log_files
            
            self.logger.info(f"Found {len(log_files)} VPC Flow Log files")
            return log_files
            
        except ClientError as e:
            handle_aws_error(e, "Listing VPC Flow Log files")
            return []
    
    def parse_flow_log_record(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse a single VPC Flow Log record.
        
        VPC Flow Log format (v2):
        version account-id interface-id srcaddr dstaddr srcport dstport protocol 
        packets bytes start end action log-status
        
        Args:
            line: Single line from VPC Flow Log
            
        Returns:
            Parsed flow log record or None if parsing fails
        """
        try:
            fields = line.strip().split()
            
            # Skip header lines
            if fields[0] == 'version' or fields[0].startswith('#'):
                return None
            
            # Parse v2 format (most common)
            if len(fields) >= 14:
                return {
                    'version': fields[0],
                    'account_id': fields[1],
                    'interface_id': fields[2],
                    'src_addr': fields[3],
                    'dst_addr': fields[4],
                    'src_port': int(fields[5]) if fields[5] != '-' else None,
                    'dst_port': int(fields[6]) if fields[6] != '-' else None,
                    'protocol': int(fields[7]) if fields[7] != '-' else None,
                    'packets': int(fields[8]) if fields[8] != '-' else None,
                    'bytes': int(fields[9]) if fields[9] != '-' else None,
                    'start': int(fields[10]),
                    'end': int(fields[11]),
                    'action': fields[12],
                    'log_status': fields[13]
                }
            else:
                return None
                
        except (ValueError, IndexError) as e:
            self.logger.debug(f"Failed to parse flow log line: {line[:100]}")
            return None
    
    def parse_log_file(self, s3_key: str) -> List[Dict[str, Any]]:
        """
        Download and parse a VPC Flow Log file from S3.
        
        Args:
            s3_key: S3 key of the VPC Flow Log file
            
        Returns:
            List of flow log records
        """
        records = []
        
        try:
            response = self.s3_client.get_object(
                Bucket=self.config.s3_bucket,
                Key=s3_key
            )
            
            # VPC Flow Logs can be gzipped
            if s3_key.endswith('.gz'):
                with gzip.GzipFile(fileobj=response['Body']) as gzipfile:
                    content = gzipfile.read().decode('utf-8')
            else:
                content = response['Body'].read().decode('utf-8')
            
            # Parse each line
            for line in content.split('\n'):
                if line.strip():
                    record = self.parse_flow_log_record(line)
                    if record:
                        records.append(record)
            
            self.logger.debug(f"Parsed {len(records)} flow records from {s3_key}")
            return records
            
        except Exception as e:
            handle_aws_error(e, f"Parsing VPC Flow Log file {s3_key}")
            return []
    
    def get_recent_flow_logs(
        self,
        hours: int = 24,
        max_records: int = 10000
    ) -> List[Dict[str, Any]]:
        """
        Get recent VPC Flow Log records.
        
        Args:
            hours: Number of hours back to look
            max_records: Maximum records to return (memory/cost control)
            
        Returns:
            List of flow log records
        """
        start_time = datetime.utcnow() - timedelta(hours=hours)
        end_time = datetime.utcnow()
        
        log_files = self.list_log_files(start_time, end_time, max_files=20)
        
        all_records = []
        for log_file in log_files:
            records = self.parse_log_file(log_file)
            all_records.extend(records)
            
            if len(all_records) >= max_records:
                self.logger.warning(f"Reached max_records limit ({max_records})")
                break
        
        return all_records[:max_records]
    
    def filter_rejected_traffic(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter flow logs to only rejected traffic (potential security events).
        
        Args:
            records: List of flow log records
            
        Returns:
            Filtered list containing only rejected traffic
        """
        return [r for r in records if r.get('action') == 'REJECT']
    
    def get_top_rejected_ports(
        self, 
        records: List[Dict[str, Any]], 
        top_n: int = 10
 ) -> List[Dict[str, Any]]:
        """
        Analyze rejected traffic to find most targeted ports.
        Helps identify port scanning or attack attempts.
        
        Args:
            records: List of flow log records
            top_n: Number of top ports to return
            
        Returns:
            List of dictionaries with port and count
        """
        rejected = self.filter_rejected_traffic(records)
        port_counts: Dict[int, int] = {}
        
        for record in rejected:
            dst_port = record.get('dst_port')
            if dst_port:
                port_counts[dst_port] = port_counts.get(dst_port, 0) + 1
        
        # Sort by count descending
        sorted_ports = sorted(
            [{'port': port, 'count': count} for port, count in port_counts.items()],
            key=lambda x: x['count'],
            reverse=True
        )
        
        return sorted_ports[:top_n]
    
    def get_top_source_ips(
        self,
        records: List[Dict[str, Any]],
        top_n: int = 10,
        rejected_only: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Get top source IPs generating traffic (potential attackers).
        
        Args:
            records: List of flow log records
            top_n: Number of top IPs to return
            rejected_only: Only count rejected traffic
            
        Returns:
            List of dictionaries with IP and count
        """
        if rejected_only:
            records = self.filter_rejected_traffic(records)
        
        ip_counts: Dict[str, int] = {}
        
        for record in records:
            src_ip = record.get('src_addr')
            if src_ip and src_ip != '-':
                ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1
        
        sorted_ips = sorted(
            [{'ip': ip, 'count': count} for ip, count in ip_counts.items()],
            key=lambda x: x['count'],
            reverse=True
        )
        
        return sorted_ips[:top_n]


class CloudTrailAnalyzer:
    """
    Analyze CloudTrail events for security-relevant patterns.
    
    This class provides methods to detect specific security events
    in CloudTrail logs without requiring expensive managed services.
    """
    
    def __init__(self):
        """Initialize CloudTrail analyzer."""
        self.logger = logging.getLogger("InfraGuard.CloudTrailAnalyzer")
    
    def find_root_account_usage(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Find instances of root account usage.
        
        Root account usage is a critical security risk. Best practice is to
        use IAM users/roles instead of root.
        
        Args:
            events: List of CloudTrail events
            
        Returns:
            List of events where root account was used
        """
        root_events = []
        
        for event in events:
            user_identity = event.get('userIdentity', {})
            if user_identity.get('type') == 'Root':
                root_events.append({
                    'event_time': event.get('eventTime'),
                    'event_name': event.get('eventName'),
                    'source_ip': event.get('sourceIPAddress'),
                    'user_agent': event.get('userAgent'),
                    'event_id': event.get('eventID')
                })
        
        if root_events:
            self.logger.warning(f"Found {len(root_events)} root account usage events")
        
        return root_events
    
    def find_failed_auth_attempts(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Find failed authentication attempts (potential brute force).
        
        Args:
            events: List of CloudTrail events
            
        Returns:
            List of failed authentication events
        """
        failed_auth = []
        
        # Common authentication failure error codes
        auth_error_codes = [
            'AccessDenied',
            'UnauthorizedOperation',
            'InvalidClientTokenId',
            'SignatureDoesNotMatch'
        ]
        
        for event in events:
            error_code = event.get('errorCode')
            if error_code in auth_error_codes:
                failed_auth.append({
                    'event_time': event.get('eventTime'),
                    'event_name': event.get('eventName'),
                    'error_code': error_code,
                    'source_ip': event.get('sourceIPAddress'),
                    'user': event.get('userIdentity', {}).get('userName', 'Unknown'),
                    'event_id': event.get('eventID')
                })
        
        if failed_auth:
            self.logger.info(f"Found {len(failed_auth)} failed authentication attempts")
        
        return failed_auth
    
    def find_privilege_escalation_attempts(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Find potential privilege escalation attempts.
        
        Looks for IAM policy changes, role assumption, and user permission modifications.
        
        Args:
            events: List of CloudTrail events
            
        Returns:
            List of potential privilege escalation events
        """
        escalation_events = []
        
        # Events that could indicate privilege escalation
        risky_events = [
            'PutUserPolicy',
            'PutRolePolicy',
            'PutGroupPolicy',
            'AttachUserPolicy',
            'AttachRolePolicy',
            'AttachGroupPolicy',
            'CreateAccessKey',
            'CreateUser',
            'AddUserToGroup',
            'UpdateAssumeRolePolicy'
        ]
        
        for event in events:
            if event.get('eventName') in risky_events:
                escalation_events.append({
                    'event_time': event.get('eventTime'),
                    'event_name': event.get('eventName'),
                    'user': event.get('userIdentity', {}).get('userName', 'Unknown'),
                    'source_ip': event.get('sourceIPAddress'),
                    'event_id': event.get('eventID')
                })
        
        if escalation_events:
            self.logger.warning(f"Found {len(escalation_events)} potential privilege escalation events")
        
        return escalation_events
