variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Name tag applied to all resources — used for identification"
  type        = string
  default     = "hng-anomaly-detector"
}

variable "instance_type" {
  description = <<-EOT
    EC2 instance type.
    t3.small  = 2 vCPU, 2 GB RAM (minimum per brief — cheapest option)
    t3.medium = 2 vCPU, 4 GB RAM (recommended for 12hr uptime stability)
  EOT
  type        = string
  default     = "t3.small"
}

variable "public_key_path" {
  description = "Path to your local SSH public key — uploaded to AWS as a key pair"
  type        = string
  default     = "~/.ssh/id_rsa.pub"
}

variable "my_ip_cidr" {
  description = <<-EOT
    Your public IP in CIDR notation — used to restrict SSH access.
    Find your IP at https://checkip.amazonaws.com then append /32.
    Example: "102.89.45.12/32"
  EOT
  type        = string
  # Replace this with your real IP before running terraform apply.
  default     = "0.0.0.0/0"
}

variable "ssm_webhook_path" {
  description = <<-EOT
    SSM Parameter Store path where the Slack webhook URL is stored as a SecureString.
    Create it once with:
      aws ssm put-parameter \
        --name "/hng-anomaly-detector/slack-webhook" \
        --value "https://hooks.slack.com/services/..." \
        --type SecureString \
        --region us-east-1
  EOT
  type    = string
  default = "/hng-anomaly-detector/slack-webhook"
}
