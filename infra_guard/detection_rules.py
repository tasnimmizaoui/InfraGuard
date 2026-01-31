"""
Detection rules for AWS security misconfigurations.
Contains security checks for IAM, Security Groups, S3, and other AWS services.
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError
import json
from .utils import (
    get_aws_client,
    get_aws_resource,
    handle_aws_error,
    is_date_older_than,
    create_finding,
    paginate_aws_call
)
from .config import Config


class SecurityChecker:
    """
    Main security checker that orchestrates all detection rules.
    """
    
    def __init__(self, config: Config):
        """
        Initialize security checker.
        
        Args:
            config: InfraGuard configuration object
        """
        self.config = config
        self.logger = logging.getLogger("InfraGuard.SecurityChecker")
        self.findings: List[Dict[str, Any]] = []
    
    def run_all_checks(self) -> List[Dict[str, Any]]:
        """
        Run all enabled security checks.
        
        Returns:
            List of security findings
        """
        self.findings = []
        
        self.logger.info("Starting security checks...")
        
        # IAM Checks
        if self.config.check_iam_unused_users:
            self.findings.extend(self.check_iam_unused_users())
        
        if self.config.check_iam_root_usage:
            self.findings.extend(self.check_iam_root_key_exists())
        
        if self.config.check_iam_overpermissive_policies:
            self.findings.extend(self.check_iam_overpermissive_policies())
        
        # Security Group Checks
        if self.config.check_security_groups:
            self.findings.extend(self.check_security_groups())
        
        # S3 Checks
        if self.config.check_s3_public_access:
            self.findings.extend(self.check_s3_public_buckets())
        
        if self.config.check_s3_encryption:
            self.findings.extend(self.check_s3_encryption())
        
        if self.config.check_s3_versioning:
            self.findings.extend(self.check_s3_versioning())

        if self.config.check_s3_bucket_policy:
            self.findings.extend(self.check_s3_bucket_policy())
        
        # CloudTrail Checks
        if self.config.check_cloudtrail_enabled:
            self.findings.extend(self.check_cloudtrail_enabled())
        
        # VPC Flow Logs Checks
        if self.config.check_vpc_flow_logs_enabled:
            self.findings.extend(self.check_vpc_flow_logs())
        
        # ECS/EKS Checks (optional, can be expensive)
        if self.config.check_ecs_containers:
            self.findings.extend(self.check_ecs_containers())
        
        self.logger.info(f"Completed all checks. Found {len(self.findings)} issues.")
        return self.findings
    
    # ==================== IAM CHECKS ====================
    
    def check_iam_unused_users(self) -> List[Dict[str, Any]]:
        """
        Check for IAM users that haven't been used recently.
        
        Unused users are a security risk as they may have been forgotten
        but still have active credentials that could be compromised.
        
        Returns:
            List of findings for unused IAM users
        """
        findings = []
        self.logger.info("Checking for unused IAM users...")
        
        try:
            iam_client = get_aws_client('iam', self.config.aws_region)
            
            # Get all IAM users
            users = paginate_aws_call(iam_client, 'list_users', 'Users')
            
            for user in users:
                username = user['UserName']
                
                # Get user's last activity
                try:
                    response = iam_client.get_user(UserName=username)
                    user_details = response['User']
                    
                    password_last_used = user_details.get('PasswordLastUsed')
                    
                    # Check if user has access keys
                    access_keys = iam_client.list_access_keys(UserName=username)
                    
                    last_used = None
                    if password_last_used:
                        last_used = password_last_used
                    
                    # Check access key last used
                    for key in access_keys.get('AccessKeyMetadata', []):
                        key_id = key['AccessKeyId']
                        key_last_used = iam_client.get_access_key_last_used(AccessKeyId=key_id)
                        key_last_used_date = key_last_used.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                        
                        if key_last_used_date:
                            if last_used is None or key_last_used_date > last_used:
                                last_used = key_last_used_date
                    
                    # Check if unused
                    if last_used is None:
                        # User has never logged in
                        findings.append(create_finding(
                            category="IAM",
                            severity="MEDIUM",
                            description=f"IAM user '{username}' has never been used",
                            resource=f"arn:aws:iam::{user.get('Arn', '').split(':')[4]}:user/{username}",
                            details={"created_date": user.get('CreateDate').isoformat() if user.get('CreateDate') else None},
                            recommendation="Consider deleting unused IAM user or investigating why it was created"
                        ))
                    elif is_date_older_than(last_used, self.config.iam_unused_threshold_days):
                        findings.append(create_finding(
                            category="IAM",
                            severity="MEDIUM",
                            description=f"IAM user '{username}' not used for {self.config.iam_unused_threshold_days}+ days",
                            resource=f"arn:aws:iam::{user.get('Arn', '').split(':')[4]}:user/{username}",
                            details={"last_used": last_used.isoformat()},
                            recommendation="Review and consider disabling or deleting this user"
                        ))
                
                except ClientError as e:
                    handle_aws_error(e, f"Checking IAM user {username}")
            
        except Exception as e:
            handle_aws_error(e, "Checking IAM unused users")
        
        return findings
    
    def check_iam_root_key_exists(self) -> List[Dict[str, Any]]:
        """
        Check if root account has access keys (major security risk).
        
        Root account should never have access keys. Use IAM users/roles instead.
        
        Returns:
            List of findings if root has access keys
        """
        findings = []
        self.logger.info("Checking for root account access keys...")
        
        try:
            iam_client = get_aws_client('iam', self.config.aws_region)
            
            # Get account summary
            summary = iam_client.get_account_summary()
            
            root_access_keys = summary.get('SummaryMap', {}).get('AccountAccessKeysPresent', 0)
            
            if root_access_keys > 0:
                findings.append(create_finding(
                    category="IAM",
                    severity="CRITICAL",
                    description="Root account has active access keys",
                    resource="AWS Root Account",
                    details={"access_key_count": root_access_keys},
                    recommendation="Immediately delete root access keys and use IAM users/roles instead"
                ))
        
        except Exception as e:
            handle_aws_error(e, "Checking root account access keys")
        
        return findings
    
    def check_iam_overpermissive_policies(self) -> List[Dict[str, Any]]:
        """
        Check for IAM policies with overly permissive permissions.
        
        Looks for policies with "*:*" or "Action": "*" which grant full access.
        
        Returns:
            List of findings for overpermissive policies
        """
        findings = []
        self.logger.info("Checking for overpermissive IAM policies...")
        
        try:
            iam_client = get_aws_client('iam', self.config.aws_region)
            
            # Check customer-managed policies
            policies = paginate_aws_call(
                iam_client, 
                'list_policies', 
                'Policies',
                Scope='Local'  # Only check customer-managed policies
            )
            
            for policy in policies:
                policy_arn = policy['Arn']
                policy_name = policy['PolicyName']
                
                try:
                    # Get policy version
                    policy_version = iam_client.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=policy['DefaultVersionId']
                    )
                    
                    policy_document = policy_version['PolicyVersion']['Document']
                    
                    # Check for overpermissive statements
                    if isinstance(policy_document, str):
                        policy_document = json.loads(policy_document)
                    
                    for statement in policy_document.get('Statement', []):
                        effect = statement.get('Effect')
                        action = statement.get('Action')
                        resource = statement.get('Resource')
                        
                        # Check for full admin access
                        if effect == 'Allow':
                            if action == '*' and resource == '*':
                                findings.append(create_finding(
                                    category="IAM",
                                    severity="HIGH",
                                    description=f"Policy '{policy_name}' grants full admin access (*:*)",
                                    resource=policy_arn,
                                    details={"statement": statement},
                                    recommendation="Follow principle of least privilege - grant only necessary permissions"
                                ))
                            elif action == '*':
                                findings.append(create_finding(
                                    category="IAM",
                                    severity="MEDIUM",
                                    description=f"Policy '{policy_name}' grants all actions on resources",
                                    resource=policy_arn,
                                    details={"statement": statement},
                                    recommendation="Restrict to specific actions needed"
                                ))
                
                except ClientError as e:
                    # Skip if we can't read the policy
                    pass
        
        except Exception as e:
            handle_aws_error(e, "Checking overpermissive IAM policies")
        
        return findings
    
    # ==================== SECURITY GROUP CHECKS ====================
    
    def check_security_groups(self) -> List[Dict[str, Any]]:
        """
        Check security groups for overly permissive rules.
        
        Looks for security groups with ports open to 0.0.0.0/0 (entire internet).
        This is a common misconfiguration that can expose services to attacks.
        
        Returns:
            List of findings for insecure security groups
        """
        findings = []
        self.logger.info("Checking security groups for open ports...")
        
        try:
            ec2_client = get_aws_client('ec2', self.config.aws_region)
            
            # Get all security groups
            response = ec2_client.describe_security_groups()
            security_groups = response.get('SecurityGroups', [])
            
            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']
                
                # Check inbound rules
                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort', 0)
                    to_port = rule.get('ToPort', 65535)
                    protocol = rule.get('IpProtocol', '-1')
                    
                    # Check for 0.0.0.0/0 access
                    for ip_range in rule.get('IpRanges', []):
                        cidr = ip_range.get('CidrIp')
                        
                        if cidr == '0.0.0.0/0':
                            # Check if it's a risky port
                            if from_port in self.config.risky_ports or to_port in self.config.risky_ports:
                                severity = "HIGH"
                                description = f"Security group '{sg_name}' has risky port {from_port}-{to_port} open to internet"
                            elif protocol == '-1':  # All protocols
                                severity = "CRITICAL"
                                description = f"Security group '{sg_name}' allows ALL traffic from internet"
                            else:
                                severity = "MEDIUM"
                                description = f"Security group '{sg_name}' has port {from_port}-{to_port} open to internet"
                            
                            findings.append(create_finding(
                                category="SecurityGroup",
                                severity=severity,
                                description=description,
                                resource=sg_id,
                                details={
                                    "group_name": sg_name,
                                    "vpc_id": sg.get('VpcId'),
                                    "protocol": protocol,
                                    "from_port": from_port,
                                    "to_port": to_port
                                },
                                recommendation="Restrict access to specific IP ranges or use AWS security groups for service-to-service communication"
                            ))
                    
                    # Check for ::/0 (IPv6 all)
                    for ipv6_range in rule.get('Ipv6Ranges', []):
                        cidr = ipv6_range.get('CidrIpv6')
                        
                        if cidr == '::/0':
                            findings.append(create_finding(
                                category="SecurityGroup",
                                severity="HIGH",
                                description=f"Security group '{sg_name}' has port {from_port}-{to_port} open to internet (IPv6)",
                                resource=sg_id,
                                details={
                                    "group_name": sg_name,
                                    "protocol": protocol,
                                    "from_port": from_port,
                                    "to_port": to_port
                                },
                                recommendation="Restrict IPv6 access to specific ranges"
                            ))
        
        except Exception as e:
            handle_aws_error(e, "Checking security groups")
        
        return findings
    
    # ==================== S3 CHECKS ====================
    
    def check_s3_public_buckets(self) -> List[Dict[str, Any]]:
        """
        Check for publicly accessible S3 buckets.
        
        Public S3 buckets can lead to data leaks and are a common misconfiguration.
        
        Returns:
            List of findings for public S3 buckets
        """
        findings = []
        self.logger.info("Checking for public S3 buckets...")
        
        try:
            # WE chose client vs ressources here , beacuse we need aws API calls that dosen't exist in resource : 
            # ACL , Bucket policy , .....
            s3_client = get_aws_client('s3', self.config.aws_region) 
            
            # List all buckets
            response = s3_client.list_buckets()
            buckets = response.get('Buckets', [])
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                try:
                    # Check bucket ACL
                    acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                    
                    for grant in acl.get('Grants', []):
                        grantee = grant.get('Grantee', {})
                        uri = grantee.get('URI', '')
                        
                        # Check for public access via ACL
                        if 'AllUsers' in uri or 'AuthenticatedUsers' in uri:
                            findings.append(create_finding(
                                category="S3",
                                severity="HIGH",
                                description=f"S3 bucket '{bucket_name}' has public ACL",
                                resource=f"arn:aws:s3:::{bucket_name}",
                                details={"grantee_uri": uri, "permission": grant.get('Permission')},
                                recommendation="Remove public ACL grants and use bucket policies for controlled access"
                            ))
                    
                    # Check public access block configuration
                    try:
                        public_access_block = s3_client.get_public_access_block(Bucket=bucket_name)
                        config = public_access_block.get('PublicAccessBlockConfiguration', {})
                        
                        if not all([
                            config.get('BlockPublicAcls', False),
                            config.get('IgnorePublicAcls', False),
                            config.get('BlockPublicPolicy', False),
                            config.get('RestrictPublicBuckets', False)
                        ]):
                            findings.append(create_finding(
                                category="S3",
                                severity="MEDIUM",
                                description=f"S3 bucket '{bucket_name}' does not have all public access blocks enabled",
                                resource=f"arn:aws:s3:::{bucket_name}",
                                details={"public_access_block_config": config},
                                recommendation="Enable all four public access block settings"
                            ))
                    
                    except ClientError as e:
                        # Public access block may not be configured
                        if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                            findings.append(create_finding(
                                category="S3",
                                severity="MEDIUM",
                                description=f"S3 bucket '{bucket_name}' has no public access block configuration",
                                resource=f"arn:aws:s3:::{bucket_name}",
                                recommendation="Configure public access block settings"
                            ))
                
                except ClientError as e:
                    if e.response['Error']['Code'] != 'NoSuchBucket':
                        handle_aws_error(e, f"Checking S3 bucket {bucket_name}")
        
        except Exception as e:
            handle_aws_error(e, "Checking S3 public buckets")
        
        return findings
    

    def check_s3_versioning(self) -> List[Dict[str, Any]]:
        """
        Check if S3 buckets have versioning enabled.
        
        Versioning helps protect against accidental deletions and overwrites.
        
        Returns:
            List of findings for S3 buckets without versioning
        """
        findings = []
        self.logger.info("Checking S3 bucket versioning...")
        
        try:
            s3_client = get_aws_client('s3', self.config.aws_region)
            
            response = s3_client.list_buckets()
            buckets = response.get('Buckets', [])
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                try:
                    versioning = s3_client.get_bucket_versioning(Bucket=bucket_name)
                    status = versioning.get('Status', 'Disabled')
                    
                    if status != 'Enabled':
                        findings.append(create_finding(
                            category="S3",
                            severity="LOW",
                            description=f"S3 bucket '{bucket_name}' does not have versioning enabled",
                            resource=f"arn:aws:s3:::{bucket_name}",
                            recommendation="Enable versioning to protect against accidental deletions/overwrites"
                        ))
                
                except ClientError as e:
                    handle_aws_error(e, f"Checking versioning for bucket {bucket_name}")
        
        except Exception as e:
            handle_aws_error(e, "Checking S3 versioning")
        
        return findings
    
    def check_s3_bucket_policy(self) -> List[Dict[str, Any]]:
        """
        Check S3 bucket policies for public access.
        Bucket policies can inadvertently allow public access.
        Returns:
            List of findings for S3 bucket policies
        """
        findings = []
        self.logger.info("Checking S3 bucket policies...")
        
        try:
            s3_client = get_aws_client('s3', self.config.aws_region)
            
            response = s3_client.list_buckets()
            buckets = response.get('Buckets', [])
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                try:
                    policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                    policy_string = policy_response.get('Policy', '{}')
                    policy = json.loads(policy_string)
                    
                    for statement in policy.get('Statement', []):
                        effect = statement.get('Effect')
                        principal = statement.get('Principal')
                        
                        if effect == 'Allow' and (principal == '*' or principal == {'AWS': '*'}):
                            findings.append(create_finding(
                                category="S3",
                                severity="HIGH",
                                description=f"S3 bucket '{bucket_name}' has a public bucket policy",
                                resource=f"arn:aws:s3:::{bucket_name}",
                                details={"statement": statement},
                                recommendation="Restrict bucket policy to specific principals"
                            ))
                
                except ClientError as e:
                    if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                        handle_aws_error(e, f"Checking bucket policy for {bucket_name}")
        
        except Exception as e:
            handle_aws_error(e, "Checking S3 bucket policies")
        
        return findings

    def check_s3_encryption(self) -> List[Dict[str, Any]]:
        """
        Check if S3 buckets have encryption enabled.
        
        Encryption at rest is a best practice for protecting sensitive data.
        
        Returns:
            List of findings for unencrypted S3 buckets

        Note: As of April 2026, SSE-C is disabled by default.
        This check verifies any encryption is configured.
        """
        findings = []
        self.logger.info("Checking S3 bucket encryption...")
        
        try:
            s3_client = get_aws_client('s3', self.config.aws_region)
            
            response = s3_client.list_buckets()
            buckets = response.get('Buckets', [])
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                try:
                    # Check for default encryption
                    encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
                    rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
                                        
                    for rule in rules:
                     sse_algorithm = rule.get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm')
            
                    # Info: Détectez SSE-C (rare après April 2026)
                    if sse_algorithm == 'SSE-C':
                        findings.append(create_finding(
                            category="S3",
                            severity="INFO",
                            description=f"Bucket '{bucket_name}' uses SSE-C (customer keys)",
                            resource=f"arn:aws:s3:::{bucket_name}",
                            recommendation="Consider migrating to SSE-KMS for better key management"
                        ))
                    
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        findings.append(create_finding(
                            category="S3",
                            severity="MEDIUM",
                            description=f"S3 bucket '{bucket_name}' does not have default encryption enabled",
                            resource=f"arn:aws:s3:::{bucket_name}",
                            recommendation="Enable default encryption (AES-256 or KMS)"
                        ))
                    else:
                        handle_aws_error(e, f"Checking encryption for bucket {bucket_name}")
        
        except Exception as e:
            handle_aws_error(e, "Checking S3 encryption")
        
        return findings
    
    # ==================== CLOUDTRAIL CHECKS ====================
    
    def check_cloudtrail_enabled(self) -> List[Dict[str, Any]]:
        """
        Check if CloudTrail is enabled and properly configured.
        
        CloudTrail is essential for audit logging and security monitoring.
        
        Returns:
            List of findings for CloudTrail configuration
        """
        findings = []
        self.logger.info("Checking CloudTrail configuration...")
        
        try:
            cloudtrail_client = get_aws_client('cloudtrail', self.config.aws_region)
            
            # List all trails
            response = cloudtrail_client.list_trails()
            trails = response.get('Trails', [])
            
            if not trails:
                findings.append(create_finding(
                    category="CloudTrail",
                    severity="HIGH",
                    description="No CloudTrail trails configured",
                    resource="AWS Account",
                    recommendation="Enable CloudTrail for audit logging"
                ))
                return findings
            
            # Check each trail
            for trail in trails:
                trail_arn = trail.get('TrailARN')
                trail_name = trail.get('Name')
                
                try:
                    # Get trail status
                    status = cloudtrail_client.get_trail_status(Name=trail_arn)
                    
                    if not status.get('IsLogging', False):
                        findings.append(create_finding(
                            category="CloudTrail",
                            severity="HIGH",
                            description=f"CloudTrail '{trail_name}' is not logging",
                            resource=trail_arn,
                            recommendation="Enable logging for this trail"
                        ))
                    
                    # Get trail configuration
                    trail_config = cloudtrail_client.get_trail(Name=trail_arn)
                    trail_details = trail_config.get('Trail', {})
                    
                    # Check if log file validation is enabled
                    if not trail_details.get('LogFileValidationEnabled', False):
                        findings.append(create_finding(
                            category="CloudTrail",
                            severity="LOW",
                            description=f"CloudTrail '{trail_name}' does not have log file validation enabled",
                            resource=trail_arn,
                            recommendation="Enable log file validation to detect tampering"
                        ))
                
                except ClientError as e:
                    handle_aws_error(e, f"Checking CloudTrail {trail_name}")
        
        except Exception as e:
            handle_aws_error(e, "Checking CloudTrail")
        
        return findings
    
    # ==================== VPC CHECKS ====================
    
    def check_vpc_flow_logs(self) -> List[Dict[str, Any]]:
        """
        Check if VPC Flow Logs are enabled for all VPCs.
        
        VPC Flow Logs are essential for network security monitoring.
        
        Returns:
            List of findings for VPCs without flow logs
        """
        findings = []
        self.logger.info("Checking VPC Flow Logs configuration...")
        
        try:
            ec2_client = get_aws_client('ec2', self.config.aws_region)
            
            # Get all VPCs
            vpcs_response = ec2_client.describe_vpcs()
            vpcs = vpcs_response.get('Vpcs', [])
            
            # Get all flow logs
            flow_logs_response = ec2_client.describe_flow_logs()
            flow_logs = flow_logs_response.get('FlowLogs', [])
            
            # Create set of VPCs with flow logs
            vpcs_with_logs = set()
            for flow_log in flow_logs:
                if flow_log.get('ResourceId', '').startswith('vpc-'):
                    vpcs_with_logs.add(flow_log['ResourceId'])
            
            # Check each VPC
            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                
                if vpc_id not in vpcs_with_logs:
                    findings.append(create_finding(
                        category="VPC",
                        severity="MEDIUM",
                        description=f"VPC '{vpc_id}' does not have Flow Logs enabled",
                        resource=vpc_id,
                        details={"vpc_cidr": vpc.get('CidrBlock')},
                        recommendation="Enable VPC Flow Logs to monitor network traffic"
                    ))
        
        except Exception as e:
            handle_aws_error(e, "Checking VPC Flow Logs")
        
        return findings
    
    # ==================== ECS/EKS CHECKS (OPTIONAL) ====================
    
    def check_ecs_containers(self) -> List[Dict[str, Any]]:
        """
        Check ECS task definitions for security misconfigurations.
        
        Optional check - ECS can incur costs beyond free tier.
        
        Returns:
            List of findings for ECS containers
        """
        findings = []
        self.logger.info("Checking ECS container configurations...")
        
        try:
            ecs_client = get_aws_client('ecs', self.config.aws_region)
            
            # List clusters
            clusters_response = ecs_client.list_clusters()
            cluster_arns = clusters_response.get('clusterArns', [])
            
            for cluster_arn in cluster_arns:
                # List task definitions in cluster
                task_defs_response = ecs_client.list_task_definitions()
                
                for task_def_arn in task_defs_response.get('taskDefinitionArns', [])[:10]:  # Limit to avoid costs
                    try:
                        task_def = ecs_client.describe_task_definition(taskDefinition=task_def_arn)
                        container_defs = task_def.get('taskDefinition', {}).get('containerDefinitions', [])
                        
                        for container in container_defs:
                            # Check for privileged mode
                            if container.get('privileged', False):
                                findings.append(create_finding(
                                    category="ECS",
                                    severity="HIGH",
                                    description=f"ECS container '{container.get('name')}' runs in privileged mode",
                                    resource=task_def_arn,
                                    recommendation="Avoid privileged mode unless absolutely necessary"
                                ))
                            
                            # Check for root user
                            if container.get('user') == 'root' or not container.get('user'):
                                findings.append(create_finding(
                                    category="ECS",
                                    severity="MEDIUM",
                                    description=f"ECS container '{container.get('name')}' may run as root user",
                                    resource=task_def_arn,
                                    recommendation="Specify a non-root user for container"
                                ))
                    
                    except ClientError as e:
                        handle_aws_error(e, f"Checking task definition {task_def_arn}")
        
        except Exception as e:
            handle_aws_error(e, "Checking ECS containers")
        
        return findings
    
    # ==================== ADDITIONAL CHECKS ====================
    
    def check_ec2_public_instances(self) -> List[Dict[str, Any]]:
        """
        Check for EC2 instances with public IP addresses.
        
        Public EC2 instances should be carefully reviewed for security.
        
        Returns:
            List of findings for public EC2 instances
        """
        findings = []
        self.logger.info("Checking for public EC2 instances...")
        
        try:
            ec2_client = get_aws_client('ec2', self.config.aws_region)
            
            # Get all instances
            reservations = paginate_aws_call(ec2_client, 'describe_instances', 'Reservations')
            
            for reservation in reservations:
                for instance in reservation.get('Instances', []):
                    instance_id = instance['InstanceId']
                    public_ip = instance.get('PublicIpAddress')
                    
                    if public_ip:
                        # Check if instance has a public IP
                        findings.append(create_finding(
                            category="EC2",
                            severity="INFO",
                            description=f"EC2 instance '{instance_id}' has public IP address",
                            resource=instance_id,
                            details={
                                "public_ip": public_ip,
                                "vpc_id": instance.get('VpcId'),
                                "state": instance.get('State', {}).get('Name')
                            },
                            recommendation="Verify this instance needs public access. Consider using NAT gateway or VPN"
                        ))
        
        except Exception as e:
            handle_aws_error(e, "Checking public EC2 instances")
        
        return findings
    
    def check_iam_password_policy(self) -> List[Dict[str, Any]]:
        """
        Check IAM password policy for weak settings.
        
        Strong password policies are essential for account security.
        
        Returns:
            List of findings for weak password policies
        """
        findings = []
        self.logger.info("Checking IAM password policy...")
        
        try:
            iam_client = get_aws_client('iam', self.config.aws_region)
            
            try:
                response = iam_client.get_account_password_policy()
                policy = response.get('PasswordPolicy', {})
                
                # Check password requirements
                if policy.get('MinimumPasswordLength', 0) < 14:
                    findings.append(create_finding(
                        category="IAM",
                        severity="MEDIUM",
                        description="IAM password policy allows passwords shorter than 14 characters",
                        resource="IAM Password Policy",
                        details={"min_length": policy.get('MinimumPasswordLength')},
                        recommendation="Set minimum password length to at least 14 characters"
                    ))
                
                if not policy.get('RequireSymbols', False):
                    findings.append(create_finding(
                        category="IAM",
                        severity="LOW",
                        description="IAM password policy does not require symbols",
                        resource="IAM Password Policy",
                        recommendation="Require symbols in passwords"
                    ))
                
                if not policy.get('RequireNumbers', False):
                    findings.append(create_finding(
                        category="IAM",
                        severity="LOW",
                        description="IAM password policy does not require numbers",
                        resource="IAM Password Policy",
                        recommendation="Require numbers in passwords"
                    ))
                
                if not policy.get('ExpirePasswords', False):
                    findings.append(create_finding(
                        category="IAM",
                        severity="LOW",
                        description="IAM password policy does not enforce password expiration",
                        resource="IAM Password Policy",
                        recommendation="Enable password expiration (e.g., 90 days)"
                    ))
            
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    findings.append(create_finding(
                        category="IAM",
                        severity="HIGH",
                        description="No IAM password policy configured",
                        resource="IAM Password Policy",
                        recommendation="Create an IAM password policy with strong requirements"
                    ))
                else:
                    handle_aws_error(e, "Getting IAM password policy")
        
        except Exception as e:
            handle_aws_error(e, "Checking IAM password policy")
        
        return findings
