---
title: 인프라 보안 - 알아야 할 핵심 개념
published: false
description: 인프라 보안의 핵심 개념들을 쉽게 설명합니다. Container 보안, Cloud 보안, Server Hardening, CI/CD 보안 등에 대해 알아봅니다.
tags: security, infrastructure, devops, cloud
cover_image: https://example.com/your-cover-image.jpg
---

# 인프라 보안 - 알아야 할 핵심 개념

현대 애플리케이션은 복잡한 인프라 위에서 실행됩니다. 컨테이너, 클라우드, CI/CD 파이프라인 등 모든 계층에서 보안이 필요합니다.

---

## 1. Container Security (Docker/Kubernetes) ⭐️⭐️⭐️

### 개념
컨테이너는 가볍고 이식 가능하지만, 잘못 설정하면 보안 위협이 됩니다.

### Docker 보안 베스트 프랙티스

**1. 최소 권한으로 실행**
```dockerfile
# ❌ root로 실행 (위험)
FROM node:18
COPY . /app
WORKDIR /app
CMD ["node", "server.js"]

# ✅ 비-root 사용자로 실행
FROM node:18-alpine
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001
USER nodejs
COPY --chown=nodejs:nodejs . /app
WORKDIR /app
CMD ["node", "server.js"]
```

**2. 최소 이미지 사용**
```dockerfile
# ❌ 큰 이미지 (불필요한 도구 포함)
FROM ubuntu:latest
RUN apt-get update && apt-get install -y nodejs npm

# ✅ Alpine 기반 최소 이미지
FROM node:18-alpine
# 최소한의 패키지만 포함
```

**3. Multi-stage Build로 비밀 정보 보호**
```dockerfile
# ✅ Multi-stage build
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
# 빌드 시에만 필요한 devDependencies
RUN npm ci
COPY . .
RUN npm run build

# 최종 이미지에는 프로덕션 파일만
FROM node:18-alpine
WORKDIR /app
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY package*.json ./
USER node
CMD ["node", "dist/server.js"]
```

**4. 이미지 스캔**
```bash
# Trivy로 취약점 스캔
trivy image myapp:latest

# Docker Scout
docker scout cves myapp:latest

# Snyk
snyk container test myapp:latest
```

### Kubernetes 보안

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
    
    # 리소스 제한
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
  
  # Ingress: 들어오는 트래픽 제한
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 3000
  
  # Egress: 나가는 트래픽 제한
  egress:
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432
```

**3. Secrets 관리**
```yaml
# ❌ ConfigMap에 비밀 정보 저장 (위험)
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  database_password: "mypassword123" # 절대 안 됨!

# ✅ Kubernetes Secrets 사용
apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
type: Opaque
stringData:
  database-password: "mypassword123"
---
# Pod에서 사용
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

**4. External Secrets Operator (권장)**
```yaml
# AWS Secrets Manager 연동
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

### AWS 보안 베스트 프랙티스

**1. IAM (Identity and Access Management)**
```json
// ❌ 과도한 권한
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "*",
    "Resource": "*"
  }]
}

// ✅ 최소 권한 원칙
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

**2. S3 Bucket 보안**
```javascript
// Terraform으로 보안 설정
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-bucket"
}

// 퍼블릭 액세스 차단
resource "aws_s3_bucket_public_access_block" "secure" {
  bucket = aws_s3_bucket.secure_bucket.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

// 암호화 활성화
resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {
  bucket = aws_s3_bucket.secure_bucket.id
  
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

// 버전 관리 활성화
resource "aws_s3_bucket_versioning" "secure" {
  bucket = aws_s3_bucket.secure_bucket.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

// 로깅 활성화
resource "aws_s3_bucket_logging" "secure" {
  bucket = aws_s3_bucket.secure_bucket.id
  
  target_bucket = aws_s3_bucket.log_bucket.id
  target_prefix = "access-logs/"
}
```

**3. VPC 보안**
```javascript
// VPC Flow Logs 활성화
resource "aws_flow_log" "main" {
  iam_role_arn    = aws_iam_role.flow_log.arn
  log_destination = aws_cloudwatch_log_group.flow_log.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.main.id
}

// Security Group - 최소 권한
resource "aws_security_group" "app" {
  name        = "app-sg"
  description = "Security group for application servers"
  vpc_id      = aws_vpc.main.id
  
  // Ingress: Load Balancer에서만
  ingress {
    from_port   = 3000
    to_port     = 3000
    protocol    = "tcp"
    security_groups = [aws_security_group.lb.id]
  }
  
  // Egress: 데이터베이스로만
  egress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    security_groups = [aws_security_group.db.id]
  }
}
```

**4. CloudTrail - 모든 API 호출 로깅**
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

### 개념
Server Hardening은 서버의 공격 표면을 최소화하는 과정입니다.

### Linux 서버 보안 설정

**1. 자동 보안 업데이트**
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

**2. SSH 보안**
```bash
# /etc/ssh/sshd_config
# Root 로그인 금지
PermitRootLogin no

# 비밀번호 인증 금지 (키만 허용)
PasswordAuthentication no
PubkeyAuthentication yes

# 포트 변경 (선택)
Port 2222

# 로그인 시도 제한
MaxAuthTries 3
MaxSessions 2

# 특정 사용자만 허용
AllowUsers deploy admin

# 서비스 재시작
systemctl restart sshd
```

**3. Fail2Ban 설정**
```bash
# 설치
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

**4. 방화벽 (UFW)**
```bash
# UFW 활성화
ufw default deny incoming
ufw default allow outgoing

# 필요한 포트만 허용
ufw allow 22/tcp   # SSH
ufw allow 80/tcp   # HTTP
ufw allow 443/tcp  # HTTPS

# 특정 IP만 허용
ufw allow from 10.0.0.0/8 to any port 5432 # PostgreSQL

ufw enable
ufw status
```

**5. 불필요한 서비스 비활성화**
```bash
# 실행 중인 서비스 확인
systemctl list-units --type=service --state=running

# 불필요한 서비스 중지
systemctl stop bluetooth
systemctl disable bluetooth

# 열린 포트 확인
netstat -tulpn
ss -tulpn
```

---

## 4. CI/CD Security ⭐️⭐️⭐️

### 개념
CI/CD 파이프라인은 프로덕션으로 가는 직접 경로이므로, 철저한 보안이 필요합니다.

### GitHub Actions 보안

**1. Secrets 관리**
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
      
      # ❌ 코드에 하드코딩 금지
      # - run: docker login -u admin -p password123
      
      # ✅ GitHub Secrets 사용
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

**2. 의존성 스캔**
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
      
      # Trivy 이미지 스캔
      - name: Build image
        run: docker build -t myapp:${{ github.sha }} .
      
      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: myapp:${{ github.sha }}
          severity: 'CRITICAL,HIGH'
          exit-code: '1'
```

**3. 코드 스캔 (SAST)**
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

### Jenkins 보안

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    environment {
        // Credentials Plugin 사용
        AWS_CREDENTIALS = credentials('aws-credentials')
        DOCKER_CREDENTIALS = credentials('docker-hub')
    }
    
    stages {
        stage('Security Scan') {
            steps {
                // 의존성 스캔
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
                // Trivy 스캔
                sh 'trivy image --severity HIGH,CRITICAL myapp:${BUILD_NUMBER}'
            }
        }
        
        stage('Deploy') {
            when {
                branch 'main'
            }
            steps {
                // 프로덕션 배포
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
            // 실패 시 알림
            slackSend channel: '#devops', 
                      color: 'danger', 
                      message: "Build failed: ${env.JOB_NAME} ${env.BUILD_NUMBER}"
        }
    }
}
```

---

## 5. OS Security Patches ⭐️⭐️

### 자동화된 패치 관리

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
  schedule = "cron(0 2 ? * SUN *)" // 매주 일요일 02:00
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

## 결론

인프라 보안 체크리스트:

### 필수 보안 조치 (⭐️⭐️⭐️)
- ✅ Container 비-root 사용자로 실행
- ✅ Kubernetes Pod Security Standards 적용
- ✅ AWS IAM 최소 권한 원칙
- ✅ CI/CD Secrets 안전하게 관리

### 중요 보안 조치 (⭐️⭐️)
- ✅ 이미지 취약점 스캔 (Trivy, Snyk)
- ✅ Server Hardening (SSH, Fail2Ban, Firewall)
- ✅ 자동 보안 업데이트
- ✅ Network Policies 설정

### 추가 보안 강화 (⭐️)
- ✅ External Secrets Operator 사용
- ✅ CloudTrail 로깅 활성화
- ✅ SAST/DAST 도구 통합
- ✅ 정기적인 패치 관리

**인프라 보안은 "Shift Left" - 개발 초기부터 보안을 고려하세요!**
