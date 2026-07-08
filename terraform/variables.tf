variable "project_name" {
  description = "Project name used as a prefix for all resources"
  type        = string
  default     = "cloudsentinel"
}

variable "environment" {
  description = "Deployment environment (dev/staging/prod)"
  type        = string
  default     = "dev"
}

variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "ap-south-1"
}

variable "vpc_cidr" {
  type    = string
  default = "10.30.0.0/16"
}

variable "public_subnet_cidr" {
  type    = string
  default = "10.30.1.0/24"
}

variable "private_subnet_cidr" {
  type    = string
  default = "10.30.2.0/24"
}

variable "scan_interval_minutes" {
  description = "How often the security scanner Lambda runs"
  type        = number
  default     = 15
}

variable "alert_email" {
  description = "Email address to receive SNS security alerts"
  type        = string
  default     = "you@example.com"
}

variable "enable_auto_remediation" {
  description = "Whether the remediation Lambda actively fixes findings or only reports them"
  type        = bool
  default     = true
}

variable "tags" {
  type = map(string)
  default = {
    Project   = "CloudSentinel"
    ManagedBy = "Terraform"
  }
}
