"""
Terraform Plan Analyzer for InfraGuard.

This module analyzes Terraform plan JSON files to detect security issues
BEFORE infrastructure is deployed (shift-left security).
"""

import json
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path

from .config import Config
from .utils import create_finding
from .policy_engine import (
    is_s3_bucket_public,
    is_s3_bucket_unencrypted,
    is_s3_versioning_disabled,
    is_s3_bucket_policy_overpermissive,
    is_s3_object_lock_disabled,
    is_security_group_overly_permissive,
    is_iam_policy_overpermissive,
    is_cloudtrail_disabled,
    is_vpc_flow_logs_disabled,
    normalize_terraform_s3_bucket,
    normalize_terraform_s3_public_access_block,
)


logger = logging.getLogger("InfraGuard.PlanAnalyzer")


class TerraformPlanAnalyzer:
    """
    Analyzes Terraform plan JSON files for security misconfigurations.
    
    This allows InfraGuard to scan PLANNED infrastructure changes before
    they are deployed, enabling shift-left security practices.
    """
    
    def __init__(self, config: Config):
        """
        Initialize Terraform plan analyzer.
        
        Args:
            config: InfraGuard configuration object
        """
        self.config = config
        self.logger = logging.getLogger("InfraGuard.PlanAnalyzer")
        self.findings: List[Dict[str, Any]] = []
        
        # Track resources by bucket name for linking related resources
        self.s3_buckets: Dict[str, Dict[str, Any]] = {}
        self.s3_bucket_configs: Dict[str, Dict[str, Any]] = {}
    
    def analyze_plan_file(self, plan_file_path: str) -> List[Dict[str, Any]]:
        """
        Analyze a Terraform plan JSON file for security issues.
        
        Args:
            plan_file_path: Path to terraform plan JSON file
                           (generated with: terraform show -json tfplan > plan.json)
        
        Returns:
            List of security findings
        """
        self.findings = []
        self.s3_buckets = {}
        self.s3_bucket_configs = {}
        
        self.logger.info(f"Analyzing Terraform plan: {plan_file_path}")
        
        # Load plan file
        try:
            with open(plan_file_path, 'r', encoding='utf-8-sig') as f:
                plan_data = json.load(f)
        except FileNotFoundError:
            self.logger.error(f"Plan file not found: {plan_file_path}")
            return []
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON in plan file: {e}")
            return []
        
        # Extract resource changes
        resource_changes = plan_data.get('resource_changes', [])
        
        if not resource_changes:
            self.logger.warning("No resource changes found in plan")
            return []
        
        self.logger.info(f"Found {len(resource_changes)} resource changes in plan")
        
        # First pass: collect all S3 buckets first
        for resource in resource_changes:
            actions = resource.get('change', {}).get('actions', [])
            
            # Only check resources being created or updated
            if 'create' not in actions and 'update' not in actions:
                continue
            
            resource_type = resource.get('type', '')
            
            if resource_type == 'aws_s3_bucket':
                resource_address = resource.get('address', '')
                bucket_name = resource.get('change', {}).get('after', {}).get('bucket')
                
                # If bucket name isn't known (e.g., uses variables), use the resource address as key
                if not bucket_name or '${' in str(bucket_name):
                    bucket_name = resource_address  # Use address as unique identifier
                
                if bucket_name:
                    self.s3_buckets[bucket_name] = resource
                    self.s3_bucket_configs[bucket_name] = normalize_terraform_s3_bucket(resource)
        
        # Second pass: collect all S3 bucket configurations
        for resource in resource_changes:
            actions = resource.get('change', {}).get('actions', [])
            
            # Only check resources being created or updated
            if 'create' not in actions and 'update' not in actions:
                continue
            
            resource_type = resource.get('type', '')
            resource_address = resource.get('address', '')
            
            if resource_type == 'aws_s3_bucket_public_access_block':
                bucket_ref = resource.get('change', {}).get('after', {}).get('bucket')
                # Try to extract bucket name from reference
                bucket_name = self._extract_bucket_name(bucket_ref, resource_address)
                self.logger.debug(f"Public access block: bucket_ref={bucket_ref}, resource_address={resource_address}, extracted_name={bucket_name}")
                self.logger.debug(f"Available buckets: {list(self.s3_bucket_configs.keys())}")
                if bucket_name and bucket_name in self.s3_bucket_configs:
                    public_access_config = normalize_terraform_s3_public_access_block(resource)
                    self.logger.info(f"Updating bucket '{bucket_name}' with public access config: {public_access_config}")
                    self.s3_bucket_configs[bucket_name].update({
                        'block_public_acls': public_access_config['block_public_acls'],
                        'block_public_policy': public_access_config['block_public_policy'],
                        'ignore_public_acls': public_access_config['ignore_public_acls'],
                        'restrict_public_buckets': public_access_config['restrict_public_buckets'],
                    })
                else:
                    self.logger.warning(f"Could not link public access block to bucket: {resource_address}")
            
            elif resource_type == 'aws_s3_bucket_versioning':
                bucket_ref = resource.get('change', {}).get('after', {}).get('bucket')
                bucket_name = self._extract_bucket_name(bucket_ref, resource_address)
                if bucket_name and bucket_name in self.s3_bucket_configs:
                    versioning_config = resource.get('change', {}).get('after', {}).get('versioning_configuration', [{}])[0]
                    status = versioning_config.get('status', 'Disabled')
                    self.s3_bucket_configs[bucket_name]['versioning_status'] = status
            
            elif resource_type == 'aws_s3_bucket_server_side_encryption_configuration':
                bucket_ref = resource.get('change', {}).get('after', {}).get('bucket')
                bucket_name = self._extract_bucket_name(bucket_ref, resource_address)
                if bucket_name and bucket_name in self.s3_bucket_configs:
                    rule = resource.get('change', {}).get('after', {}).get('rule', [{}])[0]
                    sse_config = rule.get('apply_server_side_encryption_by_default', {})
                    sse_algorithm = sse_config.get('sse_algorithm')
                    self.s3_bucket_configs[bucket_name]['sse_algorithm'] = sse_algorithm
                    self.s3_bucket_configs[bucket_name]['encryption'] = {'Rules': [rule]} if rule else None
            
            elif resource_type == 'aws_s3_bucket_policy':
                bucket_ref = resource.get('change', {}).get('after', {}).get('bucket')
                bucket_name = self._extract_bucket_name(bucket_ref, resource_address)
                if bucket_name and bucket_name in self.s3_bucket_configs:
                    policy = resource.get('change', {}).get('after', {}).get('policy')
                    self.s3_bucket_configs[bucket_name]['policy'] = policy
        
        # Second pass: run security checks
        for resource in resource_changes:
            actions = resource.get('change', {}).get('actions', [])
            
            # Only check resources being created or updated
            if 'create' not in actions and 'update' not in actions:
                continue
            
            resource_type = resource.get('type', '')
            resource_address = resource.get('address', '')
            
            # Run appropriate security checks based on resource type
            if resource_type == 'aws_s3_bucket':
                self._check_s3_bucket(resource, resource_address)
            
            elif resource_type == 'aws_security_group':
                self._check_security_group(resource, resource_address)
            
            elif resource_type == 'aws_iam_policy':
                self._check_iam_policy(resource, resource_address)
            
            elif resource_type == 'aws_iam_role_policy':
                self._check_iam_role_policy(resource, resource_address)
            
            elif resource_type == 'aws_cloudtrail':
                self._check_cloudtrail(resource, resource_address)
            
            elif resource_type == 'aws_flow_log':
                # VPC flow logs are good, no need to flag
                pass
        
        self.logger.info(f"Plan analysis complete. Found {len(self.findings)} potential issues.")
        return self.findings
    
    def _extract_bucket_name(self, bucket_ref: Any, resource_address: str) -> Optional[str]:
        """
        Extract bucket identifier from Terraform reference or resource address.
        
        Args:
            bucket_ref: Bucket reference (could be string, dict, or Terraform reference)
            resource_address: Full resource address (e.g., aws_s3_bucket_public_access_block.my_bucket_block)
        
        Returns:
            Bucket identifier (name or address) if found, None otherwise
        """
        # If it's a direct string value (actual bucket name)
        if isinstance(bucket_ref, str) and not bucket_ref.startswith('${') and '.id' not in bucket_ref:
            # Check if this bucket name exists in our configs
            if bucket_ref in self.s3_bucket_configs:
                return bucket_ref
        
        # Extract from resource address by matching naming patterns
        # Example: aws_s3_bucket_public_access_block.public_bucket_block
        #       -> aws_s3_bucket.public_bucket
        if resource_address:
            parts = resource_address.split('.')
            if len(parts) >= 2:
                resource_name = parts[-1]  # e.g., "public_bucket_block"
                
                # Try to find a bucket with a similar name
                # Common patterns: bucket_name + "_block", bucket_name + "_pab", etc.
                for suffix in ['_block', '_pab', '_public_access_block', '_versioning', '_encryption', '_policy']:
                    if resource_name.endswith(suffix):
                        potential_bucket_name = resource_name[:-len(suffix)]
                        # Build expected bucket address
                        expected_bucket_address = f"aws_s3_bucket.{potential_bucket_name}"
                        if expected_bucket_address in self.s3_bucket_configs:
                            return expected_bucket_address
                
                # Try exact match - sometimes the resource names match exactly
                expected_bucket_address = f"aws_s3_bucket.{resource_name}"
                if expected_bucket_address in self.s3_bucket_configs:
                    return expected_bucket_address
        
        return None
    
    def _check_s3_bucket(self, resource: Dict[str, Any], resource_address: str):
        """Check S3 bucket for security issues."""
        # Use resource address as bucket identifier (works even when bucket name has variables)
        bucket_identifier = resource_address
        
        if bucket_identifier not in self.s3_bucket_configs:
            return
        
        bucket_config = self.s3_bucket_configs[bucket_identifier]
        
        # Get display name (use actual bucket name if available, otherwise use resource name)
        bucket_name = resource.get('change', {}).get('after', {}).get('bucket')
        if not bucket_name or '${' in str(bucket_name):
            # Extract resource name from address for display
            bucket_name = resource_address.split('.')[-1]
        
        # Check if bucket is public
        if self.config.check_s3_public_access:
            is_public, reason = is_s3_bucket_public(bucket_config)
            if is_public:
                self.findings.append(create_finding(
                    category="S3",
                    severity="CRITICAL",
                    description=f"Planned S3 bucket '{bucket_name}' will be publicly accessible",
                    resource=resource_address,
                    details={"reason": reason, "action": "create/update"},
                    recommendation="Enable S3 Block Public Access and use private ACL"
                ))
        
        # Check encryption
        if self.config.check_s3_encryption:
            is_unencrypted, reason = is_s3_bucket_unencrypted(bucket_config)
            if is_unencrypted:
                self.findings.append(create_finding(
                    category="S3",
                    severity="HIGH",
                    description=f"Planned S3 bucket '{bucket_name}' lacks encryption",
                    resource=resource_address,
                    details={"reason": reason, "action": "create/update"},
                    recommendation="Enable default server-side encryption (AES-256 or KMS)"
                ))
        
        # Check versioning
        if self.config.check_s3_versioning:
            versioning_disabled, reason = is_s3_versioning_disabled(bucket_config)
            if versioning_disabled:
                self.findings.append(create_finding(
                    category="S3",
                    severity="MEDIUM",
                    description=f"Planned S3 bucket '{bucket_name}' has versioning disabled",
                    resource=resource_address,
                    details={"reason": reason, "action": "create/update"},
                    recommendation="Enable versioning for data protection and recovery"
                ))
        
        # Check bucket policy
        if self.config.check_s3_bucket_policy:
            is_overpermissive, reason = is_s3_bucket_policy_overpermissive(bucket_config)
            if is_overpermissive:
                self.findings.append(create_finding(
                    category="S3",
                    severity="HIGH",
                    description=f"Planned S3 bucket '{bucket_name}' has overpermissive policy",
                    resource=resource_address,
                    details={"reason": reason, "action": "create/update"},
                    recommendation="Restrict bucket policy to specific principals and actions"
                ))
        
        # Check object lock
        if self.config.check_s3_object_lock:
            object_lock_disabled, reason = is_s3_object_lock_disabled(bucket_config)
            if object_lock_disabled:
                self.findings.append(create_finding(
                    category="S3",
                    severity="LOW",
                    description=f"Planned S3 bucket '{bucket_name}' has object lock disabled",
                    resource=resource_address,
                    details={"reason": reason, "action": "create/update"},
                    recommendation="Consider enabling object lock for compliance requirements"
                ))
    
    def _check_security_group(self, resource: Dict[str, Any], resource_address: str):
        """Check security group for overly permissive rules."""
        if not self.config.check_security_groups:
            return
        
        after = resource.get('change', {}).get('after', {})
        ingress_rules = after.get('ingress', [])
        
        # Normalize ingress rules
        normalized_rules = []
        for rule in ingress_rules:
            normalized_rules.append({
                'from_port': rule.get('from_port', 0),
                'to_port': rule.get('to_port', 65535),
                'cidr_blocks': rule.get('cidr_blocks', []),
                'ipv6_cidr_blocks': rule.get('ipv6_cidr_blocks', [])
            })
        
        sg_config = {
            'group_id': after.get('id'),
            'group_name': after.get('name'),
            'ingress_rules': normalized_rules
        }
        
        is_overpermissive, reasons = is_security_group_overly_permissive(sg_config)
        
        if is_overpermissive:
            for reason in reasons:
                self.findings.append(create_finding(
                    category="Network",
                    severity="HIGH",
                    description=f"Planned security group '{sg_config.get('group_name')}' is overly permissive",
                    resource=resource_address,
                    details={"issue": reason, "action": "create/update"},
                    recommendation="Restrict ingress rules to specific IP ranges and required ports only"
                ))
    
    def _check_iam_policy(self, resource: Dict[str, Any], resource_address: str):
        """Check IAM policy for overly permissive permissions."""
        if not self.config.check_iam_overpermissive_policies:
            return
        
        after = resource.get('change', {}).get('after', {})
        policy_document = after.get('policy')
        
        policy_config = {'policy_document': policy_document}
        
        is_overpermissive, reason = is_iam_policy_overpermissive(policy_config)
        
        if is_overpermissive:
            self.findings.append(create_finding(
                category="IAM",
                severity="HIGH",
                description=f"Planned IAM policy '{after.get('name')}' is overly permissive",
                resource=resource_address,
                details={"reason": reason, "action": "create/update"},
                recommendation="Follow principle of least privilege - grant only necessary permissions"
            ))
    
    def _check_iam_role_policy(self, resource: Dict[str, Any], resource_address: str):
        """Check IAM role inline policy for overly permissive permissions."""
        if not self.config.check_iam_overpermissive_policies:
            return
        
        after = resource.get('change', {}).get('after', {})
        policy_document = after.get('policy')
        
        policy_config = {'policy_document': policy_document}
        
        is_overpermissive, reason = is_iam_policy_overpermissive(policy_config)
        
        if is_overpermissive:
            self.findings.append(create_finding(
                category="IAM",
                severity="HIGH",
                description=f"Planned IAM role policy is overly permissive",
                resource=resource_address,
                details={"reason": reason, "action": "create/update"},
                recommendation="Follow principle of least privilege - grant only necessary permissions"
            ))
    
    def _check_cloudtrail(self, resource: Dict[str, Any], resource_address: str):
        """Check CloudTrail configuration."""
        if not self.config.check_cloudtrail_enabled:
            return
        
        after = resource.get('change', {}).get('after', {})
        
        trail_config = {
            'is_logging': after.get('enable_logging', True),
            'is_multi_region': after.get('is_multi_region_trail', False),
            'include_global_service_events': after.get('include_global_service_events', True)
        }
        
        is_misconfigured, reason = is_cloudtrail_disabled(trail_config)
        
        if is_misconfigured:
            self.findings.append(create_finding(
                category="Logging",
                severity="HIGH",
                description=f"Planned CloudTrail '{after.get('name')}' is improperly configured",
                resource=resource_address,
                details={"reason": reason, "action": "create/update"},
                recommendation="Enable CloudTrail with multi-region support and global service events"
            ))
