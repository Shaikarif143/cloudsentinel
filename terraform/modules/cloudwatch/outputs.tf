output "log_group_arn" { value = aws_cloudwatch_log_group.cloudtrail.arn }
output "cloudtrail_role_arn" { value = aws_iam_role.cloudtrail_cw.arn }
