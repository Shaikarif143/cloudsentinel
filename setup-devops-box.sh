#!/bin/bash
# =============================================================================
# CloudSentinel / DevOps Practice Box — AL2023 Setup Script
# Installs: Docker, Jenkins, AWS CLI v2, Terraform, git, swap file
# Target: Amazon Linux 2023 (dnf-based), t3.small
#
# NOTE: If your instance is actually AL2 (not AL2023), swap `dnf` for `yum`
# and use `amazon-linux-extras install docker java-openjdk11` instead of the
# dnf install lines below — AL2 doesn't have amazon-linux-extras.
#
# Usage:
#   Option A (manual): scp this to the instance, then:
#     chmod +x setup-devops-box.sh && sudo ./setup-devops-box.sh
#   Option B (at launch): paste this whole file into the "User data" field
#     when launching the EC2 instance (runs automatically as root on first boot)
# =============================================================================
set -e

echo "=================================================="
echo "STEP 0: Update system packages"
echo "=================================================="
sudo dnf update -y

echo "=================================================="
echo "STEP 1: Add 2GB swap (t3.small only has 2GB RAM —
         this prevents OOM kills during Docker/Jenkins builds)"
echo "=================================================="
if [ ! -f /swapfile ]; then
  sudo dd if=/dev/zero of=/swapfile bs=1M count=2048
  sudo chmod 600 /swapfile
  sudo mkswap /swapfile
  sudo swapon /swapfile
  echo '/swapfile swap swap defaults 0 0' | sudo tee -a /etc/fstab
  echo "Swap added."
else
  echo "Swap file already exists, skipping."
fi

echo "=================================================="
echo "STEP 2: Install git, unzip, wget"
echo "=================================================="
sudo dnf install -y git unzip wget

echo "=================================================="
echo "STEP 3: Install Docker"
echo "=================================================="
sudo dnf install -y docker
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker ec2-user

echo "=================================================="
echo "STEP 4: Install Docker Compose (v2 plugin)"
echo "=================================================="
DOCKER_CONFIG=${DOCKER_CONFIG:-/usr/local/lib/docker}
sudo mkdir -p $DOCKER_CONFIG/cli-plugins
sudo curl -SL https://github.com/docker/compose/releases/latest/download/docker-compose-linux-x86_64 \
  -o $DOCKER_CONFIG/cli-plugins/docker-compose
sudo chmod +x $DOCKER_CONFIG/cli-plugins/docker-compose

echo "=================================================="
echo "STEP 5: Install Java (required for Jenkins) + Jenkins"
echo "=================================================="
sudo dnf install -y java-17-amazon-corretto

sudo wget -O /etc/yum.repos.d/jenkins.repo \
  https://pkg.jenkins.io/redhat-stable/jenkins.repo
sudo rpm --import https://pkg.jenkins.io/redhat-stable/jenkins.io-2023.key
sudo dnf install -y jenkins
sudo systemctl daemon-reload
sudo systemctl enable jenkins
# Jenkins is NOT started here by default — start it manually with
# `sudo systemctl start jenkins` when you actually want to use it,
# to keep memory free for Docker work the rest of the time.

# Let Jenkins use Docker (needed if your pipelines build/run containers)
sudo usermod -aG docker jenkins

echo "=================================================="
echo "STEP 6: Install AWS CLI v2"
echo "=================================================="
if ! command -v aws &> /dev/null || [[ "$(aws --version 2>&1)" != *"aws-cli/2"* ]]; then
  curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip"
  unzip -o /tmp/awscliv2.zip -d /tmp
  sudo /tmp/aws/install --update
  rm -rf /tmp/awscliv2.zip /tmp/aws
else
  echo "AWS CLI v2 already installed."
fi

echo "=================================================="
echo "STEP 7: Install Terraform"
echo "=================================================="
TF_VERSION="1.7.5"
curl -O "https://releases.hashicorp.com/terraform/${TF_VERSION}/terraform_${TF_VERSION}_linux_amd64.zip"
unzip -o "terraform_${TF_VERSION}_linux_amd64.zip"
sudo mv terraform /usr/local/bin/
rm -f "terraform_${TF_VERSION}_linux_amd64.zip"

echo "=================================================="
echo "STEP 8: Verify installs"
echo "=================================================="
echo "-- Docker --"
docker --version || echo "docker not on PATH yet (log out/in for group changes)"
echo "-- Docker Compose --"
docker compose version || true
echo "-- Java --"
java -version
echo "-- AWS CLI --"
aws --version
echo "-- Terraform --"
terraform --version
echo "-- Git --"
git --version

echo "=================================================="
echo "SETUP COMPLETE"
echo "=================================================="
cat << 'EOF'

NEXT STEPS:

1. Log out and back in (or run `newgrp docker`) so your user picks up
   the docker group membership without needing sudo:
     exit
     ssh -i your-key.pem ec2-user@<instance-public-ip>
     docker ps          # should work without sudo now

2. Start Jenkins only when you're actively using it:
     sudo systemctl start jenkins
     sudo systemctl status jenkins

   Get the initial admin password:
     sudo cat /var/lib/jenkins/secrets/initialAdminPassword

   Jenkins listens on port 8080 — make sure your EC2 security group
   allows inbound TCP 8080 from your IP before browsing to
   http://<instance-public-ip>:8080

   Stop it when done to free up RAM:
     sudo systemctl stop jenkins

3. Configure AWS CLI with your credentials:
     aws configure

4. Confirm swap is active:
     free -h

EOF
