resource "aws_iam_role" "config" {
  name = "${var.name_prefix}-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_config_configuration_recorder" "main" {
  name     = "${var.name_prefix}-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "${var.name_prefix}-delivery-channel"
  s3_bucket_name = var.bucket_name
  depends_on     = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

resource "aws_config_config_rule" "s3_public_read" {
  name = "${var.name_prefix}-s3-bucket-public-read-prohibited"
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "iam_mfa" {
  name = "${var.name_prefix}-iam-user-mfa-enabled"
  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_MFA_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "restricted_ssh" {
  name = "${var.name_prefix}-restricted-ssh"
  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }
  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "encrypted_volumes" {
  name = "${var.name_prefix}-encrypted-volumes"
  source {
    owner             = "AWS"
    source_identifier = "ENCRYPTED_VOLUMES"
  }
  depends_on = [aws_config_configuration_recorder.main]
}
