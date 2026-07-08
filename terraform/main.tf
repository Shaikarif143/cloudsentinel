terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
  }

  backend "s3" {
    # Configure via -backend-config, e.g.:
    # terraform init -backend-config=environments/dev.backend.conf
    # bucket         = "cloudsentinel-tf-state-<account-id>"
    # key            = "cloudsentinel/terraform.tfstate"
    # region         = "ap-south-1"
    # dynamodb_table = "cloudsentinel-tf-locks"
    # encrypt        = true
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = merge(var.tags, { Environment = var.environment })
  }
}

locals {
  name_prefix = "${var.project_name}-${var.environment}"
}

data "aws_caller_identity" "current" {}

# ---------------------------------------------------------------------------
# Networking
# ---------------------------------------------------------------------------
module "vpc" {
  source = "./modules/vpc"

  name_prefix         = local.name_prefix
  vpc_cidr            = var.vpc_cidr
  public_subnet_cidr  = var.public_subnet_cidr
  private_subnet_cidr = var.private_subnet_cidr
}

# ---------------------------------------------------------------------------
# Storage: findings tables + log archive bucket
# ---------------------------------------------------------------------------
module "dynamodb" {
  source      = "./modules/dynamodb"
  name_prefix = local.name_prefix
}

resource "aws_s3_bucket" "log_archive" {
  bucket = "${local.name_prefix}-log-archive-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_public_access_block" "log_archive" {
  bucket                  = aws_s3_bucket.log_archive.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id
  versioning_configuration {
    status = "Enabled"
  }
}

# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------
module "sns" {
  source      = "./modules/sns"
  name_prefix = local.name_prefix
  alert_email = var.alert_email
}

# ---------------------------------------------------------------------------
# CloudTrail -> CloudWatch Logs
# ---------------------------------------------------------------------------
module "cloudwatch" {
  source      = "./modules/cloudwatch"
  name_prefix = local.name_prefix
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.log_archive.id
  policy = data.aws_iam_policy_document.cloudtrail_bucket.json
}

data "aws_iam_policy_document" "cloudtrail_bucket" {
  statement {
    sid       = "AWSCloudTrailAclCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.log_archive.arn]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
  statement {
    sid       = "AWSCloudTrailWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.log_archive.arn}/cloudtrail/AWSLogs/${data.aws_caller_identity.current.account_id}/*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }
}

resource "aws_cloudtrail" "main" {
  name                          = "${local.name_prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.log_archive.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${module.cloudwatch.log_group_arn}:*"
  cloud_watch_logs_role_arn     = module.cloudwatch.cloudtrail_role_arn

  depends_on = [aws_s3_bucket_policy.cloudtrail]
}

# ---------------------------------------------------------------------------
# AWS Config + Security Hub
# ---------------------------------------------------------------------------
module "config" {
  source      = "./modules/config"
  name_prefix = local.name_prefix
  bucket_name = aws_s3_bucket.log_archive.id
}

module "securityhub" {
  source = "./modules/securityhub"
}

# ---------------------------------------------------------------------------
# Lambdas: scanner + remediation
# ---------------------------------------------------------------------------
module "lambda" {
  source = "./modules/lambda"

  name_prefix             = local.name_prefix
  dynamodb_table_arn      = module.dynamodb.table_arn
  dynamodb_table_name     = module.dynamodb.table_name
  sns_topic_arn           = module.sns.topic_arn
  scan_interval_minutes   = var.scan_interval_minutes
  enable_auto_remediation = var.enable_auto_remediation
  scanner_source_dir      = "${path.module}/../backend/lambda/scanner"
  remediation_source_dir  = "${path.module}/../backend/lambda/remediation"
}
