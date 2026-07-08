resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${var.name_prefix}"
  retention_in_days = 90
}

resource "aws_iam_role" "cloudtrail_cw" {
  name = "${var.name_prefix}-cloudtrail-cw-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "cloudtrail_cw" {
  name = "${var.name_prefix}-cloudtrail-cw-policy"
  role = aws_iam_role.cloudtrail_cw.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

resource "aws_cloudwatch_log_group" "scanner_lambda" {
  name              = "/aws/lambda/${var.name_prefix}-scanner"
  retention_in_days = 30
}

resource "aws_cloudwatch_log_group" "remediation_lambda" {
  name              = "/aws/lambda/${var.name_prefix}-remediation"
  retention_in_days = 30
}

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.name_prefix}-security-overview"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          metrics = [
            ["AWS/Lambda", "Invocations", "FunctionName", "${var.name_prefix}-scanner"],
            [".", "Errors", ".", "."]
          ]
          period = 300
          stat   = "Sum"
          region = "ap-south-1"
          title  = "Scanner Lambda Invocations / Errors"
        }
      }
    ]
  })
}
