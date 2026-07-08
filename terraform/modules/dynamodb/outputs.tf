output "table_name" { value = aws_dynamodb_table.findings.name }
output "table_arn" { value = aws_dynamodb_table.findings.arn }
output "compliance_history_table_name" { value = aws_dynamodb_table.compliance_history.name }
output "compliance_history_table_arn" { value = aws_dynamodb_table.compliance_history.arn }
