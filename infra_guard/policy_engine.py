"""
Policy Engine for InfraGuard.

This module contains reusable security policies that work with both:
1. Live AWS resources (from boto3 API responses)
2. Planned resources (from Terraform plan JSON)

Each policy function takes a normalized resource configuration and returns
whether it violates a security policy.
"""

import logging
from typing import Dict, Any, Optional, List
import json


logger = logging.getLogger("InfraGuard.PolicyEngine")


# ==================== S3 POLICIES ====================

def is_s3_bucket_public(bucket_config: Dict[str, Any]) -> tuple[bool, str]:
    """
    Check if an S3 bucket is publicly accessible.
    
    Args:
        bucket_config: Normalized bucket configuration containing:
            - acl: Bucket ACL (e.g., 'public-read', 'private')
            - block_public_acls: BlockPublicAcls setting (True/False)
            - block_public_policy: BlockPublicPolicy setting (True/False)
            - ignore_public_acls: IgnorePublicAcls setting (True/False)
            - restrict_public_buckets: RestrictPublicBuckets setting (True/False)
    
    Returns:
        Tuple of (is_public: bool, reason: str)
    """
    acl = bucket_config.get('acl', '').lower()
    
    # Check for public ACLs
    if acl in ['public-read', 'public-read-write', 'authenticated-read']:
        return True, f"Bucket has public ACL: {acl}"
    
    # Check if public access block is disabled
    block_public_acls = bucket_config.get('block_public_acls', True)
    block_public_policy = bucket_config.get('block_public_policy', True)
    ignore_public_acls = bucket_config.get('ignore_public_acls', True)
    restrict_public_buckets = bucket_config.get('restrict_public_buckets', True)
    
    if not all([block_public_acls, block_public_policy, ignore_public_acls, restrict_public_buckets]):
        disabled_settings = []
        if not block_public_acls:
            disabled_settings.append('BlockPublicAcls')
        if not block_public_policy:
            disabled_settings.append('BlockPublicPolicy')
        if not ignore_public_acls:
            disabled_settings.append('IgnorePublicAcls')
        if not restrict_public_buckets:
            disabled_settings.append('RestrictPublicBuckets')
        
        return True, f"Public access block disabled: {', '.join(disabled_settings)}"
    
    return False, "Bucket is not public"


def is_s3_bucket_unencrypted(bucket_config: Dict[str, Any]) -> tuple[bool, str]:
    """
    Check if an S3 bucket lacks encryption.
    
    Args:
        bucket_config: Normalized bucket configuration containing:
            - encryption: Encryption configuration (dict with 'Rules' or None)
            - sse_algorithm: SSE algorithm (e.g., 'AES256', 'aws:kms')
    
    Returns:
        Tuple of (is_unencrypted: bool, reason: str)
    """
    encryption = bucket_config.get('encryption')
    sse_algorithm = bucket_config.get('sse_algorithm')
    
    # No encryption configured
    if not encryption and not sse_algorithm:
        return True, "No server-side encryption configured"
    
    # Check if encryption rules exist
    if encryption:
        rules = encryption.get('Rules', [])
        if not rules:
            return True, "Encryption enabled but no rules defined"
    
    return False, f"Bucket encrypted with {sse_algorithm or 'default encryption'}"


def is_s3_versioning_disabled(bucket_config: Dict[str, Any]) -> tuple[bool, str]:
    """
    Check if S3 bucket versioning is disabled.
    
    Args:
        bucket_config: Normalized bucket configuration containing:
            - versioning_status: Versioning status ('Enabled', 'Suspended', or None)
    
    Returns:
        Tuple of (versioning_disabled: bool, reason: str)
    """
    versioning_status = bucket_config.get('versioning_status') or ''
    if isinstance(versioning_status, str):
        versioning_status = versioning_status.lower()
    else:
        versioning_status = ''
    
    if versioning_status != 'enabled':
        return True, f"Versioning is {versioning_status or 'not configured'}"
    
    return False, "Versioning is enabled"


def is_s3_bucket_policy_overpermissive(bucket_config: Dict[str, Any]) -> tuple[bool, str]:
    """
    Check if S3 bucket policy is overly permissive.
    
    Args:
        bucket_config: Normalized bucket configuration containing:
            - policy: Bucket policy JSON (dict or None)
    
    Returns:
        Tuple of (is_overpermissive: bool, reason: str)
    """
    policy = bucket_config.get('policy')
    
    if not policy:
        return False, "No bucket policy configured"
    
    # Parse policy if it's a string
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except json.JSONDecodeError:
            return False, "Unable to parse bucket policy"
    
    # Check for public access in policy statements
    for statement in policy.get('Statement', []):
        effect = statement.get('Effect', '').lower()
        principal = statement.get('Principal', {})
        
        if effect == 'allow':
            # Check for wildcard principal
            if principal == '*' or principal == {'AWS': '*'}:
                action = statement.get('Action', [])
                if isinstance(action, str):
                    action = [action]
                
                dangerous_actions = [a for a in action if 's3:Get' in a or a == 's3:*' or a == '*']
                if dangerous_actions:
                    return True, f"Public access allowed with actions: {', '.join(dangerous_actions)}"
    
    return False, "Bucket policy appears properly restricted"


def is_s3_object_lock_disabled(bucket_config: Dict[str, Any]) -> tuple[bool, str]:
    """
    Check if S3 object lock is disabled (important for compliance).
    
    Args:
        bucket_config: Normalized bucket configuration containing:
            - object_lock_enabled: Whether object lock is enabled (True/False)
            - object_lock_configuration: Object lock configuration (dict or None)
    
    Returns:
        Tuple of (object_lock_disabled: bool, reason: str)
    """
    object_lock_enabled = bucket_config.get('object_lock_enabled', False)
    object_lock_config = bucket_config.get('object_lock_configuration')
    
    if not object_lock_enabled and not object_lock_config:
        return True, "Object lock is not enabled"
    
    return False, "Object lock is enabled"


# ==================== SECURITY GROUP POLICIES ====================

def is_security_group_overly_permissive(sg_config: Dict[str, Any]) -> tuple[bool, List[str]]:
    """
    Check if security group has overly permissive rules.
    
    Args:
        sg_config: Normalized security group configuration containing:
            - ingress_rules: List of ingress rules with 'from_port', 'to_port', 'cidr_blocks'
            - egress_rules: List of egress rules
    
    Returns:
        Tuple of (is_overpermissive: bool, reasons: List[str])
    """
    reasons = []
    ingress_rules = sg_config.get('ingress_rules', [])
    
    # Common dangerous ports
    dangerous_ports = {
        22: 'SSH',
        3389: 'RDP',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        27017: 'MongoDB',
        6379: 'Redis',
        1433: 'MSSQL',
        5984: 'CouchDB'
    }
    
    for rule in ingress_rules:
        cidr_blocks = rule.get('cidr_blocks', [])
        from_port = rule.get('from_port')
        to_port = rule.get('to_port')
        
        # Check if open to internet
        if '0.0.0.0/0' in cidr_blocks or '::/0' in cidr_blocks:
            # Check for dangerous ports
            for port, service in dangerous_ports.items():
                if from_port <= port <= to_port:
                    reasons.append(f"{service} (port {port}) open to internet (0.0.0.0/0)")
            
            # Check for all ports open
            if from_port == 0 and to_port == 65535:
                reasons.append("All ports (0-65535) open to internet")
    
    return len(reasons) > 0, reasons


# ==================== IAM POLICIES ====================

def is_iam_policy_overpermissive(policy_config: Dict[str, Any]) -> tuple[bool, str]:
    """
    Check if IAM policy is overly permissive.
    
    Args:
        policy_config: Normalized IAM policy configuration containing:
            - policy_document: IAM policy document (dict)
    
    Returns:
        Tuple of (is_overpermissive: bool, reason: str)
    """
    policy_document = policy_config.get('policy_document')
    
    if not policy_document:
        return False, "No policy document provided"
    
    # Parse policy if it's a string
    if isinstance(policy_document, str):
        try:
            policy_document = json.loads(policy_document)
        except json.JSONDecodeError:
            return False, "Unable to parse policy document"
    
    for statement in policy_document.get('Statement', []):
        effect = statement.get('Effect', '').lower()
        action = statement.get('Action', [])
        resource = statement.get('Resource', [])
        
        # Convert to lists for easier checking
        if isinstance(action, str):
            action = [action]
        if isinstance(resource, str):
            resource = [resource]
        
        if effect == 'allow':
            # Check for admin access (*:*)
            if '*' in action and '*' in resource:
                return True, "Policy grants full admin access (Action: *, Resource: *)"
            
            # Check for all actions
            if '*' in action:
                return True, f"Policy grants all actions on resources: {', '.join(resource)}"
    
    return False, "Policy follows least privilege principle"


# ==================== CLOUDTRAIL POLICIES ====================

def is_cloudtrail_disabled(trail_config: Dict[str, Any]) -> tuple[bool, str]:
    """
    Check if CloudTrail is disabled or improperly configured.
    
    Args:
        trail_config: Normalized CloudTrail configuration containing:
            - is_logging: Whether trail is actively logging (True/False)
            - is_multi_region: Whether trail covers all regions (True/False)
            - include_global_service_events: Whether global events are logged (True/False)
    
    Returns:
        Tuple of (is_disabled: bool, reason: str)
    """
    is_logging = trail_config.get('is_logging', False)
    is_multi_region = trail_config.get('is_multi_region', False)
    include_global = trail_config.get('include_global_service_events', False)
    
    if not is_logging:
        return True, "CloudTrail is not logging"
    
    if not is_multi_region:
        return True, "CloudTrail is not multi-region"
    
    if not include_global:
        return True, "CloudTrail does not include global service events"
    
    return False, "CloudTrail is properly configured"


# ==================== VPC POLICIES ====================

def is_vpc_flow_logs_disabled(vpc_config: Dict[str, Any]) -> tuple[bool, str]:
    """
    Check if VPC Flow Logs are disabled.
    
    Args:
        vpc_config: Normalized VPC configuration containing:
            - flow_logs_enabled: Whether flow logs are enabled (True/False)
    
    Returns:
        Tuple of (flow_logs_disabled: bool, reason: str)
    """
    flow_logs_enabled = vpc_config.get('flow_logs_enabled', False)
    
    if not flow_logs_enabled:
        return True, "VPC Flow Logs are not enabled"
    
    return False, "VPC Flow Logs are enabled"


# ==================== NORMALIZATION HELPERS ====================

def normalize_terraform_s3_bucket(tf_resource: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize Terraform S3 bucket resource to common format.
    
    Args:
        tf_resource: Terraform resource from plan JSON
    
    Returns:
        Normalized bucket configuration for policy evaluation
    """
    after = tf_resource.get('change', {}).get('after', {})
    after_unknown = tf_resource.get('change', {}).get('after_unknown', {})
    
    return {
        'acl': after.get('acl', 'private'),
        'bucket_name': after.get('bucket'),
        'versioning_status': None,  # Will be in separate resource
        'encryption': None,  # Will be in separate resource
        'sse_algorithm': None,
        'policy': None,  # Will be in separate resource
        'object_lock_enabled': after.get('object_lock_enabled', False),
        'object_lock_configuration': after.get('object_lock_configuration'),
        # Public access block settings
        'block_public_acls': True,  # Will be in separate resource
        'block_public_policy': True,
        'ignore_public_acls': True,
        'restrict_public_buckets': True,
    }


def normalize_terraform_s3_public_access_block(tf_resource: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize Terraform S3 public access block to common format.
    
    Args:
        tf_resource: Terraform resource from plan JSON
    
    Returns:
        Normalized public access block configuration
    """
    after = tf_resource.get('change', {}).get('after', {})
    
    return {
        'bucket': after.get('bucket'),
        'block_public_acls': after.get('block_public_acls', True),
        'block_public_policy': after.get('block_public_policy', True),
        'ignore_public_acls': after.get('ignore_public_acls', True),
        'restrict_public_buckets': after.get('restrict_public_buckets', True),
    }


def normalize_boto3_s3_bucket(bucket_name: str, boto3_responses: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalize boto3 S3 bucket responses to common format.
    
    Args:
        bucket_name: Name of the S3 bucket
        boto3_responses: Dict containing boto3 API responses:
            - acl: get_bucket_acl response
            - encryption: get_bucket_encryption response
            - versioning: get_bucket_versioning response
            - policy: get_bucket_policy response
            - public_access_block: get_public_access_block response
            - object_lock: get_object_lock_configuration response
    
    Returns:
        Normalized bucket configuration for policy evaluation
    """
    acl_response = boto3_responses.get('acl', {})
    encryption_response = boto3_responses.get('encryption', {})
    versioning_response = boto3_responses.get('versioning', {})
    policy_response = boto3_responses.get('policy', {})
    public_access_block_response = boto3_responses.get('public_access_block', {})
    object_lock_response = boto3_responses.get('object_lock', {})
    
    # Determine ACL from grants
    acl = 'private'
    for grant in acl_response.get('Grants', []):
        grantee = grant.get('Grantee', {})
        if grantee.get('Type') == 'Group' and 'AllUsers' in grantee.get('URI', ''):
            permission = grant.get('Permission', '')
            if permission == 'READ':
                acl = 'public-read'
            elif permission == 'WRITE':
                acl = 'public-read-write'
    
    # Get encryption
    sse_algorithm = None
    rules = encryption_response.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
    if rules:
        sse_algorithm = rules[0].get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm')
    
    return {
        'bucket_name': bucket_name,
        'acl': acl,
        'versioning_status': versioning_response.get('Status'),
        'encryption': encryption_response.get('ServerSideEncryptionConfiguration'),
        'sse_algorithm': sse_algorithm,
        'policy': policy_response.get('Policy'),
        'object_lock_enabled': object_lock_response.get('ObjectLockEnabled') == 'Enabled',
        'object_lock_configuration': object_lock_response.get('ObjectLockConfiguration'),
        'block_public_acls': public_access_block_response.get('BlockPublicAcls', True),
        'block_public_policy': public_access_block_response.get('BlockPublicPolicy', True),
        'ignore_public_acls': public_access_block_response.get('IgnorePublicAcls', True),
        'restrict_public_buckets': public_access_block_response.get('RestrictPublicBuckets', True),
    }

