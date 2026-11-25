---
title: "Infrastructure Security - Key Concepts You Should Know"
labels: ["security","infrastructure","devops","cloud","Archive"]
published: true
date: 2025-02-03T19:16:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "11198061744781481"
source: "archive"
archivePath: "_archive/dev/security/infrastructure-security-guide-kr.md"
---

# Infrastructure Security - Key Concepts You Should Know

Modern applications run on complex infrastructure. Containers, the cloud, CI/CD pipelines - every layer needs security.

---

## 1. Container Security (Docker/Kubernetes) ⭐️⭐️⭐️

### Concept
Containers are lightweight and portable, but a bad configuration turns them into a security threat.

### Docker Security Best Practices

**1. Run with least privilege**
```dockerfile
# ❌ Running as root (dangerous)
FROM node:18
COPY . /app
WORKDIR /app
CMD ["node", "server.js"]

# ✅ Running as a non-root user
FROM node:18-alpine
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001
USER nodejs
COPY --chown=nodejs:nodejs . /app
WORKDIR /app
CMD ["node", "server.js"]
```

**2. Use a minimal image**
```dockerfile
# ❌ Large image (includes tools you don't need)
FROM ubuntu:latest
RUN apt-get update && apt-get install -y nodejs npm

# ✅ Minimal Alpine-based image
FROM node:18-alpine
# Includes only the bare minimum packages
```

**3. Protect secrets with a multi-stage build**
```dockerfile
# ✅ Multi-stage build
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
# devDependencies needed only at build time
RUN npm ci
COPY . .
RUN npm run build

# Only production files go into the final image
FROM node:18-alpine
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY package*.json ./
USER node
CMD ["node", "dist/server.js"]
```

**4. Scan your images**
```bash
# Vulnerability scan with Trivy
trivy image myapp:latest

# Docker Scout
docker scout cves myapp:latest

# Snyk
snyk container test myapp:latest
```

### Kubernetes Security

**1. Pod Security Standards**
```yaml
# pod-security-policy.yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop:
        - ALL
      readOnlyRootFilesystem: true
    
    # Resource limits
    resources:
      limits:
        memory: "128Mi"
        cpu: "500m"
      requests:
        memory: "64Mi"
        cpu: "250m"
```

**2. Network Policies**
```yaml
# network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: app-network-policy
spec:
  podSelector:
    matchLabels:
      app: myapp
  policyTypes:
  - Ingress
  - Egress
  
  # Ingress: restrict incoming traffic
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 3000
  
  # Egress: restrict outgoing traffic
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
```

**3. Managing Secrets**
```yaml
# ❌ Storing secrets in a ConfigMap (dangerous)
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  database_password: "mypassword123" # Never do this!

# ✅ Use Kubernetes Secrets
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
type: Opaque
stringData:
  database-password: "mypassword123"
---
# Using it in a Pod
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
  - name: app
    image: myapp:latest
    env:
    - name: DB_PASSWORD
      valueFrom:
        secretKeyRef:
          name: app-secrets
          key: database-password
```

**4. External Secrets Operator (recommended)**
```yaml
# AWS Secrets Manager integration
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: aws-secrets
spec:
  provider:
    aws:
      service: SecretsManager
      region: us-east-1
      auth:
        jwt:
          serviceAccountRef:
            name: external-secrets-sa
---
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: app-secrets
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets
    kind: SecretStore
  target:
    name: app-secrets
  data:
  - secretKey: database-password
    remoteRef:
      key: prod/database
      property: password
```

---

## 2. Cloud Security (AWS/Azure/GCP) ⭐️⭐️⭐️

### AWS Security Best Practices

**1. IAM (Identity and Access Management)**
```json
// ❌ Excessive permissions
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}

// ✅ Principle of least privilege
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::my-bucket/uploads/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:Query"
      ],
      "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/MyTable"
    }
  ]
}
```

**2. S3 Bucket Security**
```javascript
// Security settings with Terraform
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-bucket"
}

// Block public access
resource "aws_s3_bucket_public_access_block" "secure" {
  bucket = aws_s3_bucket.secure_bucket.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

// Enable encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {
  bucket = aws_s3_bucket.secure_bucket.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

// Enable versioning
resource "aws_s3_bucket_versioning" "secure" {
  bucket = aws_s3_bucket.secure_bucket.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

// Enable logging
resource "aws_s3_bucket_logging" "secure" {
  bucket = aws_s3_bucket.secure_bucket.id
  
  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "access-logs/"
}
```

**3. VPC Security**
```javascript
// Enable VPC Flow Logs
resource "aws_flow_log" "main" {
  iam_role_arn    = aws_iam_role.flow_log.arn
  log_destination = aws_cloudwatch_log_group.flow_log.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.main.id
}

// Security Group - least privilege
resource "aws_security_group" "app" {
  name        = "app-sg"
  description = "Security group for application servers"
  vpc_id      = aws_vpc.main.id
  
  // Ingress: only from the load balancer
  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    security_groups = [aws_security_group.lb.id]
  }
  
  // Egress: only to the database
  egress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    security_groups = [aws_security_group.db.id]
  }
}
```

**4. CloudTrail - log every API call**
```javascript
resource "aws_cloudtrail" "main" {
  name                          = "main-trail"
  s3_bucket_name               = aws_s3_bucket.cloudtrail.id
  include_global_service_events = true
  is_multi_region_trail        = true
  enable_logging               = true
  
  event_selector {
    read_write_type           = "All"
    include_management_events = true
    
    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3:::*/"]
    }
  }
}
```

---

## 3. Server Hardening ⭐️⭐️

### Concept
Server hardening is the process of minimizing a server's attack surface.

### Linux Server Security Settings

**1. Automatic security updates**
```bash
# Ubuntu/Debian
apt-get install unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades

# /etc/apt/apt.conf.d/50unattended-upgrades
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "02:00";
```

**2. SSH security**
```bash
# /etc/ssh/sshd_config
# Disallow root login
PermitRootLogin no

# Disable password authentication (keys only)
PasswordAuthentication no
PubkeyAuthentication yes

# Change the port (optional)
Port 2222

# Limit login attempts
MaxAuthTries 3
MaxSessions 2

# Allow only specific users
AllowUsers deploy admin

# Restart the service
systemctl restart sshd
```

**3. Fail2Ban setup**
```bash
# Install
apt-get install fail2ban

# /etc/fail2ban/jail.local
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 5

systemctl enable fail2ban
systemctl start fail2ban
```

**4. Firewall (UFW)**
```bash
# Enable UFW
ufw default deny incoming
ufw default allow outgoing

# Allow only the ports you need
ufw allow 22/tcp   # SSH
ufw allow 80/tcp   # HTTP
ufw allow 443/tcp  # HTTPS

# Allow only specific IPs
ufw allow from 10.0.0.0/8 to any port 5432 # PostgreSQL

ufw enable
ufw status
```

**5. Disable unnecessary services**
```bash
# List running services
systemctl list-units --type=service --state=running

# Stop unnecessary services
systemctl stop bluetooth
systemctl disable bluetooth

# Check open ports
netstat -tulpn
ss -tulpn
```

---

## 4. CI/CD Security ⭐️⭐️⭐️

### Concept
A CI/CD pipeline is a direct path to production, so it needs thorough security.

### GitHub Actions Security

**1. Managing secrets**
```yaml
# .github/workflows/deploy.yml
name: Deploy

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      # ❌ Never hardcode credentials in code
      # - run: docker login -u admin -p password123
      
      # ✅ Use GitHub Secrets
      - name: Docker Login
        env:
          DOCKER_USERNAME: ${{ secrets.DOCKER_USERNAME }}
          DOCKER_PASSWORD: ${{ secrets.DOCKER_PASSWORD }}
        run: echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin
      
      - name: Deploy
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: |
          aws ecs update-service --cluster prod --service myapp --force-new-deployment
```

**2. Dependency scanning**
```yaml
# .github/workflows/security.yml
name: Security Scan

on: [push, pull_request]

jobs:
  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      # npm audit
      - name: npm audit
        run: npm audit --audit-level=high
      
      # Snyk
      - name: Run Snyk
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      
      # Trivy image scan
      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .
      
      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
```

**3. Code scanning (SAST)**
```yaml
# .github/workflows/code-scan.yml
name: Code Security Scan

on: [push, pull_request]

jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      # CodeQL
      - name: Initialize CodeQL
        uses: github/codeql-action/init@v2
        with:
          languages: javascript
      
      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v2
      
      # SonarQube
      - name: SonarQube Scan
        uses: sonarsource/sonarcloud-github-action@master
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
```

### Jenkins Security

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    environment {
        // Use the Credentials Plugin
        AWS_CREDENTIALS = credentials('aws-credentials')
        DOCKER_CREDENTIALS = credentials('docker-hub')
    }
    
    stages {
        stage('Security Scan') {
            steps {
                // Dependency scan
                sh 'npm audit --audit-level=high'
                
                // OWASP Dependency Check
                dependencyCheck additionalArguments: '--scan ./', odcInstallation: 'DP-Check'
                dependencyCheckPublisher pattern: '**/dependency-check-report.xml'
            }
        }
        
        stage('Build') {
            steps {
                sh 'docker build -t myapp:${BUILD_NUMBER} .'
            }
        }
        
        stage('Image Scan') {
            steps {
                // Trivy scan
                sh 'trivy image --severity HIGH,CRITICAL myapp:${BUILD_NUMBER}'
            }
        }
        
        stage('Deploy') {
            when {
                branch 'main'
            }
            steps {
                // Production deployment
                sh '''
                    aws ecs update-service \
                        --cluster prod \
                        --service myapp \
                        --force-new-deployment
                '''
            }
        }
    }
    
    post {
        failure {
            // Notify on failure
            slackSend channel: '#devops', 
                      color: 'danger', 
                      message: "Build failed: ${env.JOB_NAME} ${env.BUILD_NUMBER}"
        }
    }
}
```

---

## 5. OS Security Patches ⭐️⭐️

### Automated Patch Management

**1. AWS Systems Manager Patch Manager**
```javascript
// Terraform
resource "aws_ssm_patch_baseline" "production" {
  name             = "production-baseline"
  operating_system = "AMAZON_LINUX_2"
  
  approval_rule {
    approve_after_days = 7
    
    patch_filter {
      key    = "CLASSIFICATION"
      values = ["Security", "Critical"]
    }
    
    patch_filter {
      key    = "SEVERITY"
      values = ["Critical", "Important"]
    }
  }
}

resource "aws_ssm_maintenance_window" "production" {
  name     = "production-patching"
  schedule = "cron(0 2 ? * SUN *)" // Every Sunday at 02:00
  duration = 4
  cutoff   = 1
}
```

**2. Ansible Playbook**
```yaml
# patch-servers.yml
---
- name: Update and patch servers
  hosts: all
  become: yes
  tasks:
    - name: Update apt cache
      apt:
        update_cache: yes
      when: ansible_os_family == "Debian"
    
    - name: Upgrade all packages
      apt:
        upgrade: dist
      when: ansible_os_family == "Debian"
    
    - name: Check if reboot is required
      stat:
        path: /var/run/reboot-required
      register: reboot_required
    
    - name: Reboot if required
      reboot:
        msg: "Rebooting for system updates"
        connect_timeout: 5
        reboot_timeout: 300
      when: reboot_required.stat.exists
```

---

## Conclusion

Infrastructure security checklist:

### Essential Measures (⭐️⭐️⭐️)
- ✅ Run containers as a non-root user
- ✅ Apply Kubernetes Pod Security Standards
- ✅ Follow least privilege in AWS IAM
- ✅ Manage CI/CD secrets safely

### Important Measures (⭐️⭐️)
- ✅ Scan images for vulnerabilities (Trivy, Snyk)
- ✅ Harden your servers (SSH, Fail2Ban, firewall)
- ✅ Automatic security updates
- ✅ Configure Network Policies

### Extra Hardening (⭐️)
- ✅ Use the External Secrets Operator
- ✅ Enable CloudTrail logging
- ✅ Integrate SAST/DAST tools
- ✅ Regular patch management

**Infrastructure security means "shifting left" - think about security from the very start of development!**
