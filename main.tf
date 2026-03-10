# ================================================================================================
# AIR-GAPPED MALWARE ANALYSIS INFRASTRUCTURE (HARDENED)
# Zero internet - S3 via VPC Endpoint - Separate IAM roles - Forensic-safe
# ================================================================================================

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ================================================================================================
# VARIABLES
# ================================================================================================

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "ap-south-1"
}

variable "key_pair_name" {
  description = "EC2 Key Pair name"
  type        = string
}

variable "s3_bucket_prefix" {
  description = "Unique prefix for S3 buckets"
  type        = string
  default     = "malware-analysis"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.medium"
}

variable "linux_ami_id" {
  description = "AMI ID for Linux static analysis"
  type        = string
}

variable "max_analysis_hours" {
  description = "Maximum analysis duration in hours (for cleanup tags)"
  type        = number
  default     = 2
}

variable "log_retention_days" {
  description = "Days to retain flow logs and reports"
  type        = number
  default     = 30
}

# ================================================================================================
# DATA SOURCES
# ================================================================================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ================================================================================================
# VPC - AIR-GAPPED (NO IGW, NO NAT)
# ================================================================================================

resource "aws_vpc" "malware_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "MalwareAnalysis-AirGapped-VPC" }
}

resource "aws_subnet" "private" {
  vpc_id                  = aws_vpc.malware_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = false

  tags = { Name = "MalwareAnalysis-Private-Subnet" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.malware_vpc.id
  tags   = { Name = "MalwareAnalysis-Private-RT" }
}

resource "aws_route_table_association" "private" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.private.id
}

# Explicit NACL (default allows all, but explicitly defined)
resource "aws_network_acl" "private" {
  vpc_id     = aws_vpc.malware_vpc.id
  subnet_ids = [aws_subnet.private.id]

  # Allow all internal VPC traffic
  ingress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = aws_vpc.malware_vpc.cidr_block
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = aws_vpc.malware_vpc.cidr_block
    from_port  = 0
    to_port    = 0
  }

  # Deny all external traffic (explicit)
  ingress {
    protocol   = -1
    rule_no    = 200
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = -1
    rule_no    = 200
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = { Name = "MalwareAnalysis-Private-NACL" }
}

# ================================================================================================
# VPC ENDPOINTS
# ================================================================================================

# S3 Gateway Endpoint (FREE) with POLICY
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.malware_vpc.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]

  # Endpoint policy - restrict to our buckets only
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowMalwareAnalysisBuckets"
        Effect    = "Allow"
        Principal = "*"
        Action    = ["s3:GetObject", "s3:PutObject", "s3:ListBucket"]
        Resource = [
          "arn:aws:s3:::${var.s3_bucket_prefix}-*-${data.aws_caller_identity.current.account_id}",
          "arn:aws:s3:::${var.s3_bucket_prefix}-*-${data.aws_caller_identity.current.account_id}/*"
        ]
      }
    ]
  })

  tags = { Name = "MalwareAnalysis-S3-Endpoint" }
}

# Security group for VPC endpoints (tightened - instance SGs only)
resource "aws_security_group" "vpce" {
  name        = "malware-vpce-sg"
  description = "Allow HTTPS from analysis instances only"
  vpc_id      = aws_vpc.malware_vpc.id

  tags = { Name = "MalwareAnalysis-VPCE-SG" }
}

resource "aws_security_group_rule" "vpce_ingress_static" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.static_analysis.id
  security_group_id        = aws_security_group.vpce.id
}

# SSM Endpoints
resource "aws_vpc_endpoint" "ssm" {
  vpc_id              = aws_vpc.malware_vpc.id
  service_name        = "com.amazonaws.${var.aws_region}.ssm"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private.id]
  security_group_ids  = [aws_security_group.vpce.id]
  private_dns_enabled = true

  tags = { Name = "MalwareAnalysis-SSM-Endpoint" }
}

resource "aws_vpc_endpoint" "ssm_messages" {
  vpc_id              = aws_vpc.malware_vpc.id
  service_name        = "com.amazonaws.${var.aws_region}.ssmmessages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private.id]
  security_group_ids  = [aws_security_group.vpce.id]
  private_dns_enabled = true

  tags = { Name = "MalwareAnalysis-SSMMessages-Endpoint" }
}

resource "aws_vpc_endpoint" "ec2_messages" {
  vpc_id              = aws_vpc.malware_vpc.id
  service_name        = "com.amazonaws.${var.aws_region}.ec2messages"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [aws_subnet.private.id]
  security_group_ids  = [aws_security_group.vpce.id]
  private_dns_enabled = true

  tags = { Name = "MalwareAnalysis-EC2Messages-Endpoint" }
}

# ================================================================================================
# S3 BUCKETS - HARDENED
# ================================================================================================

resource "aws_s3_bucket" "samples" {
  bucket = "${var.s3_bucket_prefix}-samples-${data.aws_caller_identity.current.account_id}"
  tags   = { Name = "Malware-Samples" }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket" "scripts" {
  bucket = "${var.s3_bucket_prefix}-scripts-${data.aws_caller_identity.current.account_id}"
  tags   = { Name = "Analysis-Scripts" }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket" "reports" {
  bucket = "${var.s3_bucket_prefix}-reports-${data.aws_caller_identity.current.account_id}"
  tags   = { Name = "Analysis-Reports" }

  lifecycle {
    prevent_destroy = true
  }
}

# VERSIONING (forensic rollback)
resource "aws_s3_bucket_versioning" "samples" {
  bucket = aws_s3_bucket.samples.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_versioning" "scripts" {
  bucket = aws_s3_bucket.scripts.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id
  versioning_configuration { status = "Enabled" }
}

# LIFECYCLE POLICIES (storage cleanup)
resource "aws_s3_bucket_lifecycle_configuration" "samples" {
  bucket = aws_s3_bucket.samples.id
  rule {
    id     = "cleanup-old-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration { noncurrent_days = var.log_retention_days }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    id     = "cleanup-old-versions"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration { noncurrent_days = var.log_retention_days }
    abort_incomplete_multipart_upload { days_after_initiation = 7 }
  }
}

# ENCRYPTION
resource "aws_s3_bucket_server_side_encryption_configuration" "samples" {
  bucket = aws_s3_bucket.samples.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "scripts" {
  bucket = aws_s3_bucket.scripts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# PUBLIC ACCESS BLOCK
resource "aws_s3_bucket_public_access_block" "samples" {
  bucket                  = aws_s3_bucket.samples.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "scripts" {
  bucket                  = aws_s3_bucket.scripts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket                  = aws_s3_bucket.reports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# BUCKET POLICIES - VPC Endpoint only for EC2, allow IAM users for management
resource "aws_s3_bucket_policy" "samples" {
  bucket     = aws_s3_bucket.samples.id
  depends_on = [aws_s3_bucket_public_access_block.samples]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonVPCEndpointForRoles"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.samples.arn, "${aws_s3_bucket.samples.arn}/*"]
        Condition = {
          StringNotEquals = { "aws:sourceVpce" = aws_vpc_endpoint.s3.id }
          ArnLike         = { "aws:PrincipalArn" = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/*" }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_policy" "scripts" {
  bucket     = aws_s3_bucket.scripts.id
  depends_on = [aws_s3_bucket_public_access_block.scripts]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonVPCEndpointForRoles"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.scripts.arn, "${aws_s3_bucket.scripts.arn}/*"]
        Condition = {
          StringNotEquals = { "aws:sourceVpce" = aws_vpc_endpoint.s3.id }
          ArnLike         = { "aws:PrincipalArn" = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/*" }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_policy" "reports" {
  bucket     = aws_s3_bucket.reports.id
  depends_on = [aws_s3_bucket_public_access_block.reports]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonVPCEndpointForRoles"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.reports.arn, "${aws_s3_bucket.reports.arn}/*"]
        Condition = {
          StringNotEquals = { "aws:sourceVpce" = aws_vpc_endpoint.s3.id }
          ArnLike         = { "aws:PrincipalArn" = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/*" }
        }
      }
    ]
  })
}

# Upload setup script
resource "aws_s3_object" "setup_script" {
  bucket = aws_s3_bucket.scripts.id
  key    = "scripts/setup.sh"
  source = "./setup.sh"
  etag   = filemd5("./setup.sh")
}

# ================================================================================================
# VPC FLOW LOGS - HARDENED
# ================================================================================================

resource "aws_s3_bucket" "flow_logs" {
  bucket = "${var.s3_bucket_prefix}-flowlogs-${data.aws_caller_identity.current.account_id}"
  tags   = { Name = "VPC-Flow-Logs" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "flow_logs" {
  bucket = aws_s3_bucket.flow_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "flow_logs" {
  bucket                  = aws_s3_bucket.flow_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "flow_logs" {
  bucket = aws_s3_bucket.flow_logs.id
  rule {
    id     = "expire-old-logs"
    status = "Enabled"
    filter {}
    expiration { days = var.log_retention_days }
  }
}

resource "aws_flow_log" "malware_vpc" {
  vpc_id               = aws_vpc.malware_vpc.id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = aws_s3_bucket.flow_logs.arn

  tags = { Name = "MalwareAnalysis-FlowLog" }
}

# ================================================================================================
# IAM ROLES - SEPARATE WITH EXPLICIT DENY
# ================================================================================================

resource "aws_iam_role" "static_analysis" {
  name = "MalwareStaticAnalysisRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { Name = "Static-Analysis-Role" }
}

# Static analysis: read samples/scripts only
resource "aws_iam_policy" "static_s3" {
  name = "MalwareStaticS3Access"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "ReadSamplesScripts"
        Effect    = "Allow"
        Action    = ["s3:GetObject"]
        Resource  = ["${aws_s3_bucket.samples.arn}/*", "${aws_s3_bucket.scripts.arn}/*"]
        Condition = { StringEquals = { "aws:sourceVpce" = aws_vpc_endpoint.s3.id } }
      },
      {
        Sid       = "WriteReports"
        Effect    = "Allow"
        Action    = ["s3:PutObject"]
        Resource  = ["${aws_s3_bucket.reports.arn}/*"]
        Condition = { StringEquals = { "aws:sourceVpce" = aws_vpc_endpoint.s3.id } }
      },
      {
        Sid    = "DenyAllElse"
        Effect = "Deny"
        Action = ["s3:*"]
        NotResource = [
          aws_s3_bucket.samples.arn, "${aws_s3_bucket.samples.arn}/*",
          aws_s3_bucket.scripts.arn, "${aws_s3_bucket.scripts.arn}/*",
          aws_s3_bucket.reports.arn, "${aws_s3_bucket.reports.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "static_s3" {
  role       = aws_iam_role.static_analysis.name
  policy_arn = aws_iam_policy.static_s3.arn
}

resource "aws_iam_role_policy_attachment" "static_ssm" {
  role       = aws_iam_role.static_analysis.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "static_analysis" {
  name = "MalwareStaticAnalysisProfile"
  role = aws_iam_role.static_analysis.name
}

# ================================================================================================
# SECURITY GROUPS - TIGHTENED
# ================================================================================================

resource "aws_security_group" "static_analysis" {
  name        = "malware-static-sg"
  description = "Static analysis - HTTPS to endpoints, inter-instance"
  vpc_id      = aws_vpc.malware_vpc.id

  # Allow from other static analysis instances (Self)
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
    description = "Self"
  }

  # HTTPS egress to VPC endpoints
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.malware_vpc.cidr_block]
    description = "HTTPS to VPC endpoints"
  }

  # Allow to other analysis instances
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
    description = "Self"
  }

  tags = { Name = "MalwareAnalysis-Static-SG" }
}


# ================================================================================================
# LAUNCH TEMPLATES - WITH CLEANUP TAGS
# ================================================================================================

data "template_file" "linux_user_data" {
  template = file("./setup.sh")
  vars     = { s3_bucket = aws_s3_bucket.scripts.id }
}

resource "aws_launch_template" "static_analysis" {
  name_prefix   = "MalwareStaticLT-"
  image_id      = var.linux_ami_id
  instance_type = var.instance_type
  key_name      = var.key_pair_name

  iam_instance_profile { name = aws_iam_instance_profile.static_analysis.name }

  network_interfaces {
    associate_public_ip_address = false
    security_groups             = [aws_security_group.static_analysis.id]
    subnet_id                   = aws_subnet.private.id
  }

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  user_data = base64encode(data.template_file.linux_user_data.rendered)

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name             = "MalwareStaticAnalysis"
      MalwareAnalysis  = "true"
      AnalysisType     = "static"
      MaxLifetimeHours = var.max_analysis_hours
      AutoTerminate    = "true"
    }
  }

  tags = { Name = "MalwareStaticAnalysisLT" }
}



# ================================================================================================
# SSM PARAMETER
# ================================================================================================

resource "aws_ssm_parameter" "config" {
  name = "/malware-analysis/config"
  type = "String"
  value = jsonencode({
    samples_bucket         = aws_s3_bucket.samples.id
    scripts_bucket         = aws_s3_bucket.scripts.id
    reports_bucket         = aws_s3_bucket.reports.id
    static_launch_template = aws_launch_template.static_analysis.id
    subnet_id              = aws_subnet.private.id
    static_security_group  = aws_security_group.static_analysis.id
    s3_vpc_endpoint        = aws_vpc_endpoint.s3.id
    max_analysis_hours     = var.max_analysis_hours
  })

  tags = { Name = "MalwareAnalysisConfig" }
}

# ================================================================================================
# OUTPUTS
# ================================================================================================

output "vpc_id" {
  value = aws_vpc.malware_vpc.id
}

output "s3_samples_bucket" {
  value = aws_s3_bucket.samples.id
}

output "s3_scripts_bucket" {
  value = aws_s3_bucket.scripts.id
}

output "s3_reports_bucket" {
  value = aws_s3_bucket.reports.id
}

output "s3_vpc_endpoint_id" {
  value = aws_vpc_endpoint.s3.id
}

output "ssm_config_name" {
  value = aws_ssm_parameter.config.name
}

output "static_launch_template_id" {
  value = aws_launch_template.static_analysis.id
}

