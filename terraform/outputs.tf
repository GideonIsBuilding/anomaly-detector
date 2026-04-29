output "server_ip" {
  description = "Static public IP of your server (Elastic IP)"
  value       = aws_eip.hng.public_ip
}

output "ssh_command" {
  description = "SSH command to connect to the server"
  value       = "ssh ubuntu@${aws_eip.hng.public_ip}"
}

output "nextcloud_url" {
  description = "Nextcloud accessible at this URL (IP only — no domain needed)"
  value       = "http://${aws_eip.hng.public_ip}"
}

output "dashboard_url" {
  description = "Anomaly detector live metrics dashboard"
  value       = "http://${aws_eip.hng.public_ip}:8080"
}

output "instance_id" {
  description = "EC2 instance ID — useful for AWS console lookups"
  value       = aws_instance.hng.id
}

output "ami_used" {
  description = "Ubuntu AMI that was selected for this region"
  value       = data.aws_ami.ubuntu.id
}
