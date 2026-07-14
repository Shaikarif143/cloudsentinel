data "archive_file" "scanner_zip" {
  type        = "zip"
  source_dir  = var.scanner_source_dir
  output_path = "${path.module}/build/scanner.zip"
  excludes    = ["__pycache__", "*.pyc", "tests"]
}

data "archive_file" "remediation_zip" {
  type        = "zip"
  source_dir  = var.remediation_source_dir
  output_path = "${path.module}/build/remediation.zip"
  excludes    = ["__pycache__", "*.pyc", "tests"]
}

# ---------------- Scanner role (read-only audit) ----------------
resource "aws_iam_role" "scanner" {
  name = "${var.name_prefix}-scanner-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "scanner" {
  name = "${var.name_prefix}-scanner-policy"
  role = aws_iam_role.scanner.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadOnlyAudit"
        Effect = "Allow"
        Action = [
          "iam:ListUsers",
          "iam:ListAccessKeys",
          "iam:ListMFADevices",
          "iam:GetLoginProfile",
          "iam:ListAttachedUserPolicies",
          "iam:ListEntitiesForPolicy",
          "iam:GetAccountPasswordPolicy",
          "iam:GenerateCredentialReport",
          "iam:GetCredentialReport",
          "ec2:DescribeInstances",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeVolumes",
          "ec2:DescribeImages",
          "ec2:DescribeAddresses",
          "s3:ListAllMyBuckets",
          "s3:GetBucketAcl",
          "s3:GetBucketPolicyStatus",
          "s3:GetBucketPolicy",
          "s3:GetEncryptionConfiguration",
          "s3:GetBucketVersioning",
          "s3:GetBucketPublicAccessBlock",
          "securityhub:BatchImportFindings"
        ]
        Resource = "*"
      },
      {
        Sid      = "WriteFindings"
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:Query", "dynamodb:BatchWriteItem"]
        Resource = [
          var.dynamodb_table_arn,
          "${var.dynamodb_table_arn}/index/*",
          var.compliance_history_table_arn
        ]
      },
      {
        Sid      = "Notify"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = var.sns_topic_arn
      },
      {
        Sid      = "InvokeRemediation"
        Effect   = "Allow"
        Action   = ["lambda:InvokeFunction"]
        Resource = aws_lambda_function.remediation.arn
      },
      {
        Sid      = "Logs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# ---------------- Remediation role (narrow write) ----------------
resource "aws_iam_role" "remediation" {
  name = "${var.name_prefix}-remediation-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "remediation" {
  name = "${var.name_prefix}-remediation-policy"
  role = aws_iam_role.remediation.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "RemediationActions"
        Effect = "Allow"
        Action = [
          "s3:PutBucketPublicAccessBlock",
          "s3:PutEncryptionConfiguration",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:DeleteSecurityGroup",
          "ec2:CreateTags"
        ]
        Resource = "*"
      },
      {
        Sid      = "WriteFindings"
        Effect   = "Allow"
        Action   = ["dynamodb:UpdateItem", "dynamodb:PutItem", "dynamodb:Query"]
        Resource = [var.dynamodb_table_arn, "${var.dynamodb_table_arn}/index/*"]
      },
      {
        Sid      = "Notify"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = var.sns_topic_arn
      },
      {
        Sid      = "Logs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

resource "aws_lambda_function" "scanner" {
  function_name    = "${var.name_prefix}-scanner"
  role             = aws_iam_role.scanner.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  timeout          = 120
  memory_size      = 256
  filename         = data.archive_file.scanner_zip.output_path
  source_code_hash = data.archive_file.scanner_zip.output_base64sha256

  environment {
    variables = {
      FINDINGS_TABLE      = var.dynamodb_table_name
      SNS_TOPIC_ARN       = var.sns_topic_arn
      REMEDIATION_FN_NAME = aws_lambda_function.remediation.function_name
      AUTO_REMEDIATE      = tostring(var.enable_auto_remediation)
    }
  }
}

resource "aws_lambda_function" "remediation" {
  function_name    = "${var.name_prefix}-remediation"
  role             = aws_iam_role.remediation.arn
  handler          = "handler.lambda_handler"
  runtime          = "python3.12"
  timeout          = 60
  memory_size      = 128
  filename         = data.archive_file.remediation_zip.output_path
  source_code_hash = data.archive_file.remediation_zip.output_base64sha256

  environment {
    variables = {
      FINDINGS_TABLE = var.dynamodb_table_name
      SNS_TOPIC_ARN  = var.sns_topic_arn
    }
  }
}

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${var.name_prefix}-scan-schedule"
  schedule_expression = "rate(${var.scan_interval_minutes} minutes)"
}

resource "aws_cloudwatch_event_target" "scanner" {
  rule      = aws_cloudwatch_event_rule.schedule.name
  target_id = "scanner-lambda"
  arn       = aws_lambda_function.scanner.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scanner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}
