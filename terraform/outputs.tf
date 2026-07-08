output "vpc_id" {
  value = module.vpc.vpc_id
}
output "dynamodb_table_name" {
  value = module.dynamodb.table_name
}
output "sns_topic_arn" {
  value = module.sns.topic_arn
}
output "scanner_lambda_name" {
  value = module.lambda.scanner_function_name
}
output "remediation_lambda_name" {
  value = module.lambda.remediation_function_name
}
output "log_archive_bucket" {
  value = aws_s3_bucket.log_archive.id
}
