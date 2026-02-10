---
title: 네트워크 보안 - 알아야 할 핵심 개념
published: false
description: 네트워크 보안의 핵심 개념들을 쉽게 설명합니다. DDoS 방어, DNS 보안, CDN 보안, Load Balancer 보안 등에 대해 알아봅니다.
tags: security, network, infrastructure, devops
cover_image: https://example.com/your-cover-image.jpg
---

# 네트워크 보안 - 알아야 할 핵심 개념

네트워크는 모든 서비스의 기반이며, 네트워크 보안은 전체 시스템 보안의 첫 번째 방어선입니다. 이 글에서는 실무에서 반드시 알아야 할 네트워크 보안 개념들을 다룹니다.

---

## 1. DDoS (Distributed Denial of Service) 방어 ⭐️⭐️⭐️

### 개념
DDoS는 다수의 시스템을 이용해 대상 서버에 대량의 트래픽을 보내 서비스를 마비시키는 공격입니다.

### DDoS 공격 유형

**1. Volume-based Attacks (대역폭 공격)**
```bash
# UDP Flood - 대량의 UDP 패킷 전송
# ICMP Flood (Ping Flood) - Ping 요청 남발
# 목표: 대역폭 소진

# 증상 확인
netstat -an | grep -c UDP  # UDP 연결 수
```

**2. Protocol Attacks (프로토콜 공격)**
```bash
# SYN Flood - TCP 3-way handshake 악용
# 연결 요청만 보내고 완료하지 않음

# 확인
netstat -an | grep SYN_RECV | wc -l

# Ping of Death - 비정상적으로 큰 ping 패킷
```

**3. Application Layer Attacks (애플리케이션 계층 공격)**
```javascript
// HTTP Flood - 대량의 HTTP 요청
// Slowloris - 연결을 천천히 보내 서버 리소스 고갈

// 예시: 초당 수천 개의 요청
for (let i = 0; i < 10000; i++) {
  fetch('https://target.com/expensive-api');
}
```

### DDoS 방어 방법

**1. Rate Limiting (애플리케이션 레벨)**
```javascript
const rateLimit = require('express-rate-limit');

// IP당 요청 수 제한
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15분
  max: 100, // 최대 100개 요청
  message: '너무 많은 요청입니다.',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', limiter);

// 더 엄격한 제한 (로그인 등)
const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true, // 성공한 요청은 카운트 안 함
});

app.post('/api/login', strictLimiter, loginHandler);
```

**2. Cloudflare DDoS Protection**
```javascript
// Cloudflare 설정 (DNS 레벨)
// 1. Cloudflare에 도메인 등록
// 2. DNS 레코드 설정
// 3. DDoS Protection 자동 활성화

// Cloudflare API로 보안 레벨 설정
const cloudflare = require('cloudflare');
const cf = cloudflare({
  email: process.env.CF_EMAIL,
  key: process.env.CF_API_KEY
});

// Security Level 설정
await cf.zones.settings.edit('zone_id', {
  items: [
    {
      id: 'security_level',
      value: 'high' // essentially_off, low, medium, high, under_attack
    }
  ]
});
```

**3. AWS Shield & WAF**
```javascript
// AWS Shield Standard: 자동으로 활성화 (무료)
// AWS Shield Advanced: 추가 보호 (유료)

// AWS WAF 규칙 설정
const AWS = require('aws-sdk');
const waf = new AWS.WAFV2();

// Rate-based rule 생성
const params = {
  Name: 'RateLimitRule',
  Scope: 'REGIONAL',
  DefaultAction: { Allow: {} },
  Rules: [
    {
      Name: 'RateLimit',
      Priority: 1,
      Statement: {
        RateBasedStatement: {
          Limit: 2000, // 5분당 2000 요청
          AggregateKeyType: 'IP'
        }
      },
      Action: { Block: {} },
      VisibilityConfig: {
        SampledRequestsEnabled: true,
        CloudWatchMetricsEnabled: true,
        MetricName: 'RateLimitRule'
      }
    }
  ]
};

await waf.createWebACL(params).promise();
```

**4. Nginx Rate Limiting**
```nginx
# nginx.conf
http {
    # IP당 초당 10개 요청 제한
    limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;
    
    # 연결 수 제한
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    
    server {
        location /api/ {
            limit_req zone=mylimit burst=20 nodelay;
            limit_conn addr 10;
            
            proxy_pass http://backend;
        }
        
        # 특정 경로는 더 엄격하게
        location /api/login {
            limit_req zone=mylimit burst=5 nodelay;
            proxy_pass http://backend;
        }
    }
}
```

---

## 2. DNS Security ⭐️⭐️⭐️

### 개념
DNS는 도메인 이름을 IP 주소로 변환하는 시스템으로, DNS 공격은 서비스를 완전히 마비시킬 수 있습니다.

### DNS 공격 유형

**1. DNS Spoofing (DNS 스푸핑)**
```bash
# 공격자가 가짜 DNS 응답을 보내 사용자를 악성 사이트로 유도

# 방어: DNSSEC 사용
# Domain Name System Security Extensions
```

**2. DNS Amplification Attack**
```bash
# 공격자가 출발지 IP를 피해자로 위조하여 DNS 서버에 대량 요청
# DNS 서버가 피해자에게 큰 응답 전송

# 방어: DNS 서버 설정
options {
    rate-limit {
        responses-per-second 10;
    };
};
```

### DNSSEC 설정

```bash
# DNSSEC 활성화 (Cloudflare 예시)
# 1. Cloudflare 대시보드 → DNS 탭
# 2. DNSSEC 섹션 → Enable DNSSEC

# 수동 DNSSEC 설정 (BIND9)
# 키 생성
dnssec-keygen -a RSASHA256 -b 2048 -n ZONE example.com
dnssec-keygen -a RSASHA256 -b 2048 -f KSK -n ZONE example.com

# Zone 서명
dnssec-signzone -o example.com -k Kexample.com.+008+12345.key \
    example.com.zone Kexample.com.+008+54321.key

# 확인
dig +dnssec example.com
```

### DNS over HTTPS (DoH) & DNS over TLS (DoT)

```javascript
// Node.js에서 DNS over HTTPS 사용
const doh = require('dns-over-https');

const resolver = new doh.DohResolver('https://cloudflare-dns.com/dns-query');

// DNS 쿼리
resolver.query('example.com', 'A').then(response => {
  console.log(response.answers);
});
```

```nginx
# Nginx에서 DoH 프록시 설정
server {
    listen 443 ssl http2;
    server_name dns.example.com;
    
    location /dns-query {
        proxy_pass https://1.1.1.1/dns-query;
        proxy_set_header Host cloudflare-dns.com;
    }
}
```

---

## 3. CDN Security ⭐️⭐️

### 개념
CDN(Content Delivery Network)은 콘텐츠를 전 세계에 분산하여 제공하지만, 잘못 설정하면 보안 위협이 될 수 있습니다.

### CDN 보안 설정

**1. Origin 서버 보호**
```nginx
# Nginx - CDN IP만 허용
# Cloudflare IP 화이트리스트
geo $is_cf {
    default 0;
    103.21.244.0/22 1;
    103.22.200.0/22 1;
    103.31.4.0/22 1;
    # ... Cloudflare IP 범위
}

server {
    location / {
        if ($is_cf = 0) {
            return 403;
        }
        
        # Origin 서버 직접 접근 차단
        # CDN을 통해서만 접근 가능
    }
}
```

**2. CDN 인증 (Signed URLs)**
```javascript
// AWS CloudFront Signed URLs
const AWS = require('aws-sdk');
const cloudfront = new AWS.CloudFront.Signer(
  process.env.CF_KEY_PAIR_ID,
  process.env.CF_PRIVATE_KEY
);

// 시간 제한이 있는 URL 생성
const signedUrl = cloudfront.getSignedUrl({
  url: 'https://cdn.example.com/video.mp4',
  expires: Math.floor(Date.now() / 1000) + 3600 // 1시간 후 만료
});

// Cloudflare Signed URLs
const crypto = require('crypto');

function generateSignedUrl(path, secret, expiry) {
  const exp = Math.floor(Date.now() / 1000) + expiry;
  const toSign = `${path}${exp}`;
  const signature = crypto
    .createHmac('sha256', secret)
    .update(toSign)
    .digest('hex');
  
  return `${path}?exp=${exp}&sig=${signature}`;
}
```

**3. Cache Poisoning 방지**
```nginx
# Nginx - Cache Key 정규화
proxy_cache_key "$scheme$request_method$host$request_uri$is_args$args";

# Vary 헤더 제한
proxy_ignore_headers Vary;

# 안전하지 않은 헤더 무시
proxy_ignore_headers X-Accel-Expires Expires Cache-Control;
```

```javascript
// Express.js - Cache-Control 설정
app.use((req, res, next) => {
  // 민감한 데이터는 캐시하지 않음
  if (req.path.startsWith('/api/user')) {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  } else {
    res.set('Cache-Control', 'public, max-age=3600');
  }
  next();
});
```

---

## 4. Load Balancer Security ⭐️⭐️

### 개념
Load Balancer는 트래픽을 여러 서버에 분산하지만, 잘못 설정하면 보안 취약점이 됩니다.

### Load Balancer 보안 설정

**1. SSL/TLS Termination**
```yaml
# AWS Application Load Balancer
Resources:
  MyALB:
    Type: AWS::ElasticLoadBalancingV2::LoadBalancer
    Properties:
      SecurityGroups:
        - !Ref ALBSecurityGroup
      Subnets:
        - !Ref PublicSubnet1
        - !Ref PublicSubnet2

  HTTPSListener:
    Type: AWS::ElasticLoadBalancingV2::Listener
    Properties:
      DefaultActions:
        - Type: forward
          TargetGroupArn: !Ref MyTargetGroup
      LoadBalancerArn: !Ref MyALB
      Port: 443
      Protocol: HTTPS
      Certificates:
        - CertificateArn: !Ref MyCertificate
      SslPolicy: ELBSecurityPolicy-TLS-1-2-2017-01
```

**2. Nginx Load Balancer**
```nginx
upstream backend {
    # IP Hash로 세션 유지
    ip_hash;
    
    # 백엔드 서버
    server 10.0.1.10:3000 weight=3;
    server 10.0.1.11:3000 weight=2;
    server 10.0.1.12:3000 backup;
    
    # Health check
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name example.com;
    
    # SSL 설정
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # 보안 헤더
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    
    location / {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # 타임아웃 설정
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

**3. Health Check**
```javascript
// Express.js Health Check Endpoint
app.get('/health', (req, res) => {
  // 데이터베이스 연결 확인
  db.ping()
    .then(() => {
      res.status(200).json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
      });
    })
    .catch(() => {
      res.status(503).json({
        status: 'unhealthy',
        timestamp: new Date().toISOString()
      });
    });
});

// 더 상세한 Health Check
app.get('/health/detailed', async (req, res) => {
  const checks = {
    database: await checkDatabase(),
    redis: await checkRedis(),
    externalApi: await checkExternalApi()
  };
  
  const allHealthy = Object.values(checks).every(c => c.healthy);
  
  res.status(allHealthy ? 200 : 503).json({
    status: allHealthy ? 'healthy' : 'unhealthy',
    checks,
    timestamp: new Date().toISOString()
  });
});
```

---

## 5. Network Segmentation ⭐️⭐️

### 개념
네트워크 세분화는 네트워크를 여러 구역으로 나누어 공격 범위를 제한하는 기법입니다.

### VPC (Virtual Private Cloud) 설계

```yaml
# AWS VPC 구조
VPC: 10.0.0.0/16

Public Subnets (인터넷 접근 가능):
  - Public Subnet 1: 10.0.1.0/24 (AZ-1)
  - Public Subnet 2: 10.0.2.0/24 (AZ-2)
  → Load Balancer, NAT Gateway

Private Subnets (인터넷 접근 불가):
  - Private Subnet 1: 10.0.10.0/24 (AZ-1)
  - Private Subnet 2: 10.0.11.0/24 (AZ-2)
  → Application Servers

Database Subnets (완전히 격리):
  - DB Subnet 1: 10.0.20.0/24 (AZ-1)
  - DB Subnet 2: 10.0.21.0/24 (AZ-2)
  → RDS, ElastiCache
```

### Security Groups 설정

```yaml
# Load Balancer Security Group
LoadBalancerSG:
  Inbound:
    - Port: 80, Source: 0.0.0.0/0 (HTTP from anywhere)
    - Port: 443, Source: 0.0.0.0/0 (HTTPS from anywhere)
  Outbound:
    - Port: 3000, Destination: AppServerSG (to app servers)

# Application Server Security Group
AppServerSG:
  Inbound:
    - Port: 3000, Source: LoadBalancerSG (from LB only)
    - Port: 22, Source: BastionSG (SSH from bastion only)
  Outbound:
    - Port: 5432, Destination: DatabaseSG (to DB only)
    - Port: 443, Destination: 0.0.0.0/0 (HTTPS to internet)

# Database Security Group
DatabaseSG:
  Inbound:
    - Port: 5432, Source: AppServerSG (from app servers only)
  Outbound:
    - None (no outbound allowed)
```

### Zero Trust Network

```javascript
// Zero Trust 원칙: "Never trust, always verify"

// 모든 요청에 인증 필요
app.use('/api', authenticateToken);

// 네트워크 위치가 아닌 ID 기반 접근 제어
function checkAccess(user, resource, action) {
  // 1. 사용자 인증 확인
  if (!user.authenticated) return false;
  
  // 2. 사용자 권한 확인
  if (!user.permissions.includes(action)) return false;
  
  // 3. 리소스 소유권 확인
  if (resource.ownerId !== user.id && user.role !== 'admin') {
    return false;
  }
  
  // 4. 컨텍스트 기반 확인 (시간, 위치 등)
  if (!isValidContext(user, resource)) return false;
  
  return true;
}
```

---

## 6. SSL/TLS 최적화 및 보안 ⭐️⭐️

### 최신 TLS 설정

```nginx
# Nginx - 최신 TLS 설정
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';

# OCSP Stapling (인증서 검증 성능 향상)
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /path/to/chain.pem;
resolver 1.1.1.1 8.8.8.8 valid=300s;

# Session Cache (성능 향상)
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_session_tickets off;

# HSTS
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

### SSL Labs A+ 등급 받기

```javascript
// Let's Encrypt 자동 갱신
const certbot = require('certbot');

// Certbot 설정
const config = {
  domains: ['example.com', 'www.example.com'],
  email: 'admin@example.com',
  webroot: '/var/www/html'
};

// 자동 갱신 크론잡 (매일 실행)
// 0 0 * * * certbot renew --quiet
```

---

## 7. 네트워크 모니터링 ⭐️⭐️

### 실시간 트래픽 모니터링

```bash
# tcpdump - 패킷 캡처
tcpdump -i eth0 port 80 -w capture.pcap

# Wireshark로 분석
wireshark capture.pcap

# netstat - 네트워크 연결 확인
netstat -tunlp | grep :80

# iftop - 실시간 대역폭 모니터링
iftop -i eth0
```

```javascript
// Node.js - 네트워크 메트릭 수집
const os = require('os');
const si = require('systeminformation');

async function getNetworkMetrics() {
  const networkStats = await si.networkStats();
  
  return {
    interfaces: networkStats.map(iface => ({
      iface: iface.iface,
      rx_bytes: iface.rx_bytes,
      tx_bytes: iface.tx_bytes,
      rx_sec: iface.rx_sec,
      tx_sec: iface.tx_sec
    })),
    connections: await si.networkConnections()
  };
}

// Prometheus 메트릭으로 export
const promClient = require('prom-client');

const networkBytesCounter = new promClient.Counter({
  name: 'network_bytes_total',
  help: 'Total network bytes',
  labelNames: ['direction', 'interface']
});

setInterval(async () => {
  const metrics = await getNetworkMetrics();
  // 메트릭 업데이트
}, 10000);
```

---

## 결론

네트워크 보안 체크리스트:

### 필수 보안 조치 (⭐️⭐️⭐️)
- ✅ DDoS 방어 (Cloudflare, AWS Shield)
- ✅ DNSSEC 활성화
- ✅ TLS 1.2+ 사용

### 중요 보안 조치 (⭐️⭐️)
- ✅ CDN Origin 서버 보호
- ✅ Load Balancer SSL Termination
- ✅ Network Segmentation (VPC, Security Groups)
- ✅ SSL/TLS 최적화

### 추가 보안 강화 (⭐️)
- ✅ DNS over HTTPS (DoH)
- ✅ Zero Trust Network 구현
- ✅ 실시간 네트워크 모니터링

**네트워크 보안은 계층적 방어(Defense in Depth)가 핵심입니다. 단일 보안 장치에 의존하지 말고, 여러 계층의 보안을 구축하세요.**
