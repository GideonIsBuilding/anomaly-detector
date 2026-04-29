#!/bin/bash
# user_data.sh — runs once on first boot as root.
# Installs Docker, clones the repo, fetches the Slack webhook from SSM,
# and injects it into config.yaml.
#
# Template variables (injected by Terraform's templatefile()):
#   ssm_webhook_path — SSM parameter path for the Slack webhook URL
#   aws_region       — AWS region where the parameter is stored

set -euo pipefail

# Log all output so you can debug via: cat /var/log/user_data.log
exec > /var/log/user_data.log 2>&1

echo "=== [1/7] System update ==="
apt-get update -y
apt-get upgrade -y

echo "=== [2/7] Install dependencies ==="
apt-get install -y \
  ca-certificates \
  curl \
  gnupg \
  git \
  iptables \
  ufw \
  awscli

echo "=== [3/7] Install Docker ==="
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  | tee /etc/apt/sources.list.d/docker.list > /dev/null

apt-get update -y
apt-get install -y \
  docker-ce \
  docker-ce-cli \
  containerd.io \
  docker-compose-plugin

usermod -aG docker ubuntu

echo "=== [4/7] Enable Docker on boot ==="
systemctl enable docker
systemctl start docker

echo "=== [5/7] Configure firewall ==="
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 8080/tcp
ufw --force enable

echo "=== [6/7] Clone repository ==="
cd /home/ubuntu
git clone https://github.com/GideonIsBuilding/anomaly-detector.git
chown -R ubuntu:ubuntu anomaly-detector

echo "=== [7/7] Inject Slack webhook from SSM ==="
WEBHOOK=$(aws ssm get-parameter \
  --name "${ssm_webhook_path}" \
  --with-decryption \
  --query "Parameter.Value" \
  --output text \
  --region "${aws_region}")

sed -i "s|webhook_url:.*|webhook_url: \"$WEBHOOK\"|" \
  /home/ubuntu/anomaly-detector/detector/config.yaml

echo "=== Bootstrap complete ==="
echo "Next steps:"
echo "  1. SSH in: ssh ubuntu@<SERVER_IP>"
echo "  2. Start the stack: cd anomaly-detector && docker compose up -d --build"
