---
title: "Network Security - Key Concepts You Should Know"
labels: ["security","network","infrastructure","devops","Archive"]
published: true
date: 2025-02-11T09:01:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "4843827415752530288"
source: "archive"
archivePath: "_archive/dev/security/network-security-guide-kr.md"
---

# Network Security - Key Concepts You Should Know

The network is the foundation of every service, and network security is the first line of defense for the whole system. This post covers the network security concepts you really need to know in practice.

---

## 1. DDoS (Distributed Denial of Service) Defense ⭐️⭐️⭐️

### Concept
A DDoS attack uses many systems to flood a target server with traffic until the service goes down.

### Types of DDoS Attacks

**1. Volume-based attacks (bandwidth attacks)**
```bash
# UDP Flood - sends a massive number of UDP packets
# ICMP Flood (Ping Flood) - spams ping requests
# Goal: exhaust bandwidth

# Check for symptoms
netstat -an | grep -c UDP  # Number of UDP connections
```

**2. Protocol attacks**
```bash
# SYN Flood - abuses the TCP 3-way handshake
# Sends connection requests but never completes them

# Check
netstat -an | grep SYN_RECV | wc -l

# Ping of Death - abnormally large ping packets
```

**3. Application layer attacks**
```javascript
// HTTP Flood - a massive number of HTTP requests
// Slowloris - sends connections slowly to exhaust server resources

// Example: thousands of requests per second
for (let i = 0; i < 10000; i++) {
  fetch('https://target.com/expensive-api');
}
```

### How to Defend Against DDoS

**1. Rate limiting (application level)**
```javascript
const rateLimit = require('express-rate-limit');

// Limit requests per IP
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Up to 100 requests
  message: 'Too many requests.',
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', limiter);

// Stricter limit (login, etc.)
const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  skipSuccessfulRequests: true, // Don't count successful requests
});

app.post('/api/login', strictLimiter, loginHandler);
```

**2. Cloudflare DDoS Protection**
```javascript
// Cloudflare setup (DNS level)
// 1. Add your domain to Cloudflare
// 2. Configure DNS records
// 3. DDoS Protection is enabled automatically

// Set the security level via the Cloudflare API
const cloudflare = require('cloudflare');
const cf = cloudflare({
  email: process.env.CF_EMAIL,
  key: process.env.CF_API_KEY
});

// Set the Security Level
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
// AWS Shield Standard: enabled automatically (free)
// AWS Shield Advanced: extra protection (paid)

// Configure AWS WAF rules
const AWS = require('aws-sdk');
const waf = new AWS.WAFV2();

// Create a rate-based rule
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
          Limit: 2000, // 2000 requests per 5 minutes
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

**4. Nginx rate limiting**
```nginx
# nginx.conf
http {
    # Limit each IP to 10 requests per second
    limit_req_zone $binary_remote_addr zone=mylimit:10m rate=10r/s;
    
    # Limit the number of connections
    limit_conn_zone $binary_remote_addr zone=addr:10m;
    
    server {
        location /api/ {
            limit_req zone=mylimit burst=20 nodelay;
            limit_conn addr 10;
            
            proxy_pass http://backend;
        }
        
        # Stricter limits for specific paths
        location /api/login {
            limit_req zone=mylimit burst=5 nodelay;
            proxy_pass http://backend;
        }
    }
}
```

---

## 2. DNS Security ⭐️⭐️⭐️

### Concept
DNS is the system that translates domain names into IP addresses, and a DNS attack can take a service down completely.

### Types of DNS Attacks

**1. DNS spoofing**
```bash
# The attacker sends fake DNS responses to lure users to a malicious site

# Defense: use DNSSEC
# Domain Name System Security Extensions
```

**2. DNS amplification attack**
```bash
# The attacker spoofs the source IP as the victim's and floods DNS servers with requests
# The DNS servers send large responses to the victim

# Defense: DNS server configuration
options {
    rate-limit {
        responses-per-second 10;
    };
};
```

### Setting Up DNSSEC

```bash
# Enable DNSSEC (Cloudflare example)
# 1. Cloudflare dashboard → DNS tab
# 2. DNSSEC section → Enable DNSSEC

# Manual DNSSEC setup (BIND9)
# Generate keys
dnssec-keygen -a RSASHA256 -b 2048 -n ZONE example.com
dnssec-keygen -a RSASHA256 -b 2048 -f KSK -n ZONE example.com

# Sign the zone
dnssec-signzone -o example.com -k Kexample.com.+008+12345.key \
    example.com.zone Kexample.com.+008+54321.key

# Verify
dig +dnssec example.com
```

### DNS over HTTPS (DoH) & DNS over TLS (DoT)

```javascript
// Using DNS over HTTPS in Node.js
const doh = require('dns-over-https');

const resolver = new doh.DohResolver('https://cloudflare-dns.com/dns-query');

// DNS query
resolver.query('example.com', 'A').then(response => {
  console.log(response.answers);
});
```

```nginx
# DoH proxy setup in Nginx
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

### Concept
A CDN (Content Delivery Network) distributes content around the world, but a misconfigured one can become a security threat.

### CDN Security Settings

**1. Protect the origin server**
```nginx
# Nginx - allow only CDN IPs
# Cloudflare IP allowlist
geo $is_cf {
    default 0;
    103.21.244.0/22 1;
    103.22.200.0/22 1;
    103.31.4.0/22 1;
    # ... Cloudflare IP ranges
}

server {
    location / {
        if ($is_cf = 0) {
            return 403;
        }
        
        # Block direct access to the origin server
        # Accessible only through the CDN
    }
}
```

**2. CDN authentication (signed URLs)**
```javascript
// AWS CloudFront Signed URLs
const AWS = require('aws-sdk');
const cloudfront = new AWS.CloudFront.Signer(
  process.env.CF_KEY_PAIR_ID,
  process.env.CF_PRIVATE_KEY
);

// Generate a time-limited URL
const signedUrl = cloudfront.getSignedUrl({
  url: 'https://cdn.example.com/video.mp4',
  expires: Math.floor(Date.now() / 1000) + 3600 // Expires in 1 hour
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

**3. Preventing cache poisoning**
```nginx
# Nginx - normalize the cache key
proxy_cache_key "$scheme$request_method$host$request_uri$is_args$args";

# Restrict the Vary header
proxy_ignore_headers Vary;

# Ignore unsafe headers
proxy_ignore_headers X-Accel-Expires Expires Cache-Control;
```

```javascript
// Express.js - set Cache-Control
app.use((req, res, next) => {
  // Don't cache sensitive data
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

### Concept
A load balancer spreads traffic across multiple servers, but a misconfigured one becomes a security weakness.

### Load Balancer Security Settings

**1. SSL/TLS termination**
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

**2. Nginx load balancer**
```nginx
upstream backend {
    # Keep sessions sticky with IP hash
    ip_hash;
    
    # Backend servers
    server 10.0.1.10:3000 weight=3;
    server 10.0.1.11:3000 weight=2;
    server 10.0.1.12:3000 backup;
    
    # Health check
    keepalive 32;
}

server {
    listen 443 ssl http2;
    server_name example.com;
    
    # SSL settings
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    
    location / {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeout settings
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
}
```

**3. Health check**
```javascript
// Express.js Health Check Endpoint
app.get('/health', (req, res) => {
  // Check the database connection
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

// A more detailed health check
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

### Concept
Network segmentation splits a network into multiple zones to limit the blast radius of an attack.

### VPC (Virtual Private Cloud) Design

```yaml
# AWS VPC layout
VPC: 10.0.0.0/16

Public Subnets (internet-accessible):
  - Public Subnet 1: 10.0.1.0/24 (AZ-1)
  - Public Subnet 2: 10.0.2.0/24 (AZ-2)
  → Load Balancer, NAT Gateway

Private Subnets (no internet access):
  - Private Subnet 1: 10.0.10.0/24 (AZ-1)
  - Private Subnet 2: 10.0.11.0/24 (AZ-2)
  → Application Servers

Database Subnets (fully isolated):
  - DB Subnet 1: 10.0.20.0/24 (AZ-1)
  - DB Subnet 2: 10.0.21.0/24 (AZ-2)
  → RDS, ElastiCache
```

### Security Group Settings

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
// Zero Trust principle: "Never trust, always verify"

// Every request requires authentication
app.use('/api', authenticateToken);

// Identity-based access control, not network-location-based
function checkAccess(user, resource, action) {
  // 1. Verify the user is authenticated
  if (!user.authenticated) return false;
  
  // 2. Check the user's permissions
  if (!user.permissions.includes(action)) return false;
  
  // 3. Check resource ownership
  if (resource.ownerId !== user.id && user.role !== 'admin') {
    return false;
  }
  
  // 4. Context-based checks (time, location, etc.)
  if (!isValidContext(user, resource)) return false;
  
  return true;
}
```

---

## 6. SSL/TLS Optimization and Security ⭐️⭐️

### Modern TLS Configuration

```nginx
# Nginx - modern TLS configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384';

# OCSP Stapling (faster certificate validation)
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /path/to/chain.pem;
resolver 1.1.1.1 8.8.8.8 valid=300s;

# Session cache (better performance)
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;
ssl_session_tickets off;

# HSTS
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
```

### Getting an A+ on SSL Labs

```javascript
// Let's Encrypt auto-renewal
const certbot = require('certbot');

// Certbot configuration
const config = {
  domains: ['example.com', 'www.example.com'],
  email: 'admin@example.com',
  webroot: '/var/www/html'
};

// Auto-renewal cron job (runs daily)
// 0 0 * * * certbot renew --quiet
```

---

## 7. Network Monitoring ⭐️⭐️

### Real-Time Traffic Monitoring

```bash
# tcpdump - capture packets
tcpdump -i eth0 port 80 -w capture.pcap

# Analyze with Wireshark
wireshark capture.pcap

# netstat - check network connections
netstat -tunlp | grep :80

# iftop - real-time bandwidth monitoring
iftop -i eth0
```

```javascript
// Node.js - collect network metrics
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

// Export as Prometheus metrics
const promClient = require('prom-client');

const networkBytesCounter = new promClient.Counter({
  name: 'network_bytes_total',
  help: 'Total network bytes',
  labelNames: ['direction', 'interface']
});

setInterval(async () => {
  const metrics = await getNetworkMetrics();
  // Update metrics
}, 10000);
```

---

## Conclusion

Network security checklist:

### Essential Measures (⭐️⭐️⭐️)
- ✅ DDoS defense (Cloudflare, AWS Shield)
- ✅ Enable DNSSEC
- ✅ Use TLS 1.2+

### Important Measures (⭐️⭐️)
- ✅ Protect the CDN origin server
- ✅ SSL termination at the load balancer
- ✅ Network segmentation (VPC, Security Groups)
- ✅ SSL/TLS optimization

### Extra Hardening (⭐️)
- ✅ DNS over HTTPS (DoH)
- ✅ Implement a Zero Trust network
- ✅ Real-time network monitoring

**The key to network security is defense in depth. Don't rely on a single security control - build multiple layers of protection.**
