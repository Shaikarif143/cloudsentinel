resource "aws_sns_topic" "alerts" {
  name = "${var.name_prefix}-security-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_sns_topic_policy" "alerts" {
  arn    = aws_sns_topic.alerts.arn
  policy = data.aws_iam_policy_document.sns_policy.json
}

data "aws_iam_policy_document" "sns_policy" {
  statement {
    effect    = "Allow"
    actions   = ["SNS:Publish"]
    resources = [aws_sns_topic.alerts.arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com", "lambda.amazonaws.com"]
    }
  }
}
