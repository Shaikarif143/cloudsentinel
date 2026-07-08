resource "aws_dynamodb_table" "findings" {
  name         = "${var.name_prefix}-findings"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_id"
  range_key    = "scan_timestamp"

  attribute {
    name = "finding_id"
    type = "S"
  }
  attribute {
    name = "scan_timestamp"
    type = "S"
  }
  attribute {
    name = "severity"
    type = "S"
  }
  attribute {
    name = "resource_type"
    type = "S"
  }

  global_secondary_index {
    name            = "severity-index"
    hash_key        = "severity"
    range_key       = "scan_timestamp"
    projection_type = "ALL"
  }

  global_secondary_index {
    name            = "resource-type-index"
    hash_key        = "resource_type"
    range_key       = "scan_timestamp"
    projection_type = "ALL"
  }

  point_in_time_recovery {
    enabled = true
  }
  server_side_encryption {
    enabled = true
  }

  tags = { Name = "${var.name_prefix}-findings" }
}

resource "aws_dynamodb_table" "compliance_history" {
  name         = "${var.name_prefix}-compliance-history"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "scan_date"

  attribute {
    name = "scan_date"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }

  tags = { Name = "${var.name_prefix}-compliance-history" }
}
