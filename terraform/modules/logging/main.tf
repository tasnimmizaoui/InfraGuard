# ============================================
# Logging Module - CloudTrail and VPC Flow Logs
# ============================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ============================================
# CloudTrail Configuration
# ============================================

resource "aws_cloudtrail" "infraguard" {
  name                          = var.cloudtrail_name
  s3_bucket_name                = var.s3_bucket_name
  s3_key_prefix                 = var.cloudtrail_s3_prefix
  include_global_service_events = true
  is_multi_region_trail         = var.multi_region_trail
  enable_log_file_validation    = true
  enable_logging                = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  tags = merge(
    var.tags,
    {
      Name        = "InfraGuard CloudTrail"
      Description = "CloudTrail for security monitoring"
    }
  )

  depends_on = [var.s3_bucket_policy_id]
}

# ============================================
# VPC Flow Logs Configuration
# ============================================

# Get default VPC
data "aws_vpc" "default" {
  count   = var.enable_vpc_flow_logs ? 1 : 0
  default = true
}

# Create VPC Flow Logs for default VPC
resource "aws_flow_log" "default_vpc" {
  count                    = var.enable_vpc_flow_logs ? 1 : 0
  vpc_id                   = data.aws_vpc.default[0].id
  traffic_type             = "ALL"
  log_destination_type     = "s3"
  log_destination          = "${var.s3_bucket_arn}/${var.vpc_flow_logs_s3_prefix}"
  max_aggregation_interval = 600 # 10 minutes (cheaper than 1 minute)

  tags = merge(
    var.tags,
    {
      Name        = "InfraGuard VPC Flow Logs - Default VPC"
      Description = "VPC Flow Logs for security monitoring"
    }
  )

  depends_on = [var.s3_bucket_policy_id]
}

# Optional: Create flow logs for additional VPCs
resource "aws_flow_log" "additional_vpcs" {
  for_each                 = toset(var.additional_vpc_ids)
  vpc_id                   = each.value
  traffic_type             = "ALL"
  log_destination_type     = "s3"
  log_destination          = "${var.s3_bucket_arn}/${var.vpc_flow_logs_s3_prefix}"
  max_aggregation_interval = 600

  tags = merge(
    var.tags,
    {
      Name        = "InfraGuard VPC Flow Logs - ${each.value}"
      Description = "VPC Flow Logs for security monitoring"
    }
  )

  depends_on = [var.s3_bucket_policy_id]
}
 