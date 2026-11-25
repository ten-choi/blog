---
title: "SSDLC - A Guide to the Secure Software Development Lifecycle"
labels: ["security","ssdlc","devops","sast","dast","code-review","Archive"]
published: true
date: 2025-02-21T16:59:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "7243728851501018506"
source: "archive"
archivePath: "_archive/dev/security/ssdlc-guide-kr.md"
---

# SSDLC - A Guide to the Secure Software Development Lifecycle

SSDLC (Secure Software Development Lifecycle) is an approach that builds security into every phase of software development. Instead of bolting security on at the end, you bake it in from the start.

---

## 1. SSDLC Overview ⭐️⭐️⭐️

### Traditional SDLC vs SSDLC

```javascript
// ❌ Traditional SDLC (security comes last)
Plan → Design → Develop → Test → Deploy → [Security Review] ← Way too late!

// ✅ SSDLC (security integrated into every phase)
[Security Requirements] → [Secure Design] → [Secure Coding] → [Security Testing] → [Secure Deployment] → [Monitoring]
```

### Benefits of SSDLC

```javascript
/*
1. Early vulnerability detection
   - Fixing issues found early in development is up to 100x cheaper

2. A security culture
   - Developers become security-aware

3. Compliance
   - Meets regulations such as GDPR and PCI-DSS

4. More customer trust
   - Prevents security incidents

5. Lower costs
   - Prevention is cheaper than cleaning up afterwards
*/
```

---

## 2. Phase 1: Requirements Gathering and Planning

### Defining Security Requirements

```markdown
## Security Requirements Checklist

### Authentication and Authorization
- [ ] Multi-factor authentication (MFA) support
- [ ] Role-based access control (RBAC)
- [ ] Session timeout (30 minutes)
- [ ] Password policy (at least 12 characters, including special characters)

### Data Protection
- [ ] Encryption in transit (TLS 1.3)
- [ ] Encryption at rest (AES-256)
- [ ] Masking of sensitive data
- [ ] Data backup and recovery

### Logging and Monitoring
- [ ] Security event logging
- [ ] Real-time intrusion detection
- [ ] Audit trail

### Compliance
- [ ] GDPR compliance
- [ ] PCI-DSS compliance (payment systems)
- [ ] Privacy policy

### Infrastructure Security
- [ ] WAF (Web Application Firewall)
- [ ] DDoS protection
- [ ] Regular vulnerability scans
```

### Threat Modeling

```javascript
// The STRIDE model

/*
S - Spoofing
  Threat: impersonating another user
  Mitigation: strong authentication, MFA

T - Tampering
  Threat: unauthorized modification of data
  Mitigation: input validation, integrity checks

R - Repudiation
  Threat: denying an action was performed
  Mitigation: audit logs, digital signatures

I - Information Disclosure
  Threat: leaking sensitive information
  Mitigation: encryption, access control

D - Denial of Service
  Threat: taking the service down
  Mitigation: rate limiting, CDN

E - Elevation of Privilege
  Threat: hijacking admin privileges
  Mitigation: principle of least privilege, RBAC
*/
```

### Attack Tree Example

```javascript
// Attack scenario: taking over a user account

/*
[Goal: take over a user account]
    │
    ├─ [AND] Obtain the password
    │   ├─ [OR] Brute Force
    │   │   └─ Mitigation: Rate Limiting, CAPTCHA
    │   ├─ [OR] Phishing
    │   │   └─ Mitigation: security training, 2FA
    │   └─ [OR] SQL Injection
    │       └─ Mitigation: Prepared Statements
    │
    └─ [AND] Hijack the session
        ├─ [OR] XSS
        │   └─ Mitigation: CSP, Input Sanitization
        └─ [OR] CSRF
            └─ Mitigation: CSRF Token
*/
```

---

## 3. Phase 2: Design

### Secure Architecture Design Principles

```javascript
/*
1. Defense in Depth
   - Multiple layers of security controls

2. Least Privilege
   - Grant only the minimum permissions needed

3. Fail Secure
   - Fall back to a safe state when an error occurs

4. Deny by Default
   - Allow access only to what is explicitly permitted

5. Complete Mediation
   - Verify every access

6. Open Design
   - Security should rely on the design, not on secrecy
*/
```

### Secure Design Patterns

```javascript
// 1. Secure by Default
class UserService {
  constructor() {
    // Defaults are as restrictive as possible
    this.defaultPermissions = {
      read: false,
      write: false,
      delete: false,
      admin: false
    };
  }
  
  createUser(userData) {
    return {
      ...userData,
      permissions: this.defaultPermissions,
      mfaEnabled: true,  // MFA enabled by default
      sessionTimeout: 30 * 60 * 1000  // 30 minutes
    };
  }
}

// 2. Input Validation Layer
class ValidationLayer {
  static validateInput(data, schema) {
    // Every input must pass through the validation layer
    const validated = schema.validate(data);
    
    if (validated.error) {
      throw new ValidationError(validated.error.message);
    }
    
    return validated.value;
  }
}

// 3. Secure Configuration
class SecurityConfig {
  constructor() {
    // Load safely from environment variables
    this.jwtSecret = process.env.JWT_SECRET;
    this.encryptionKey = process.env.ENCRYPTION_KEY;
    
    if (!this.jwtSecret || !this.encryptionKey) {
      throw new Error('Required security settings are missing');
    }
    
    // Disable debug mode in production
    this.debugMode = process.env.NODE_ENV !== 'production';
  }
}
```

---

## 4. Phase 3: Development (Secure Coding)

### Secure Coding Checklist

```javascript
/*
✅ Input validation
  - Validate every input
  - Prefer an allowlist approach
  - Be careful with regular expressions

✅ Output encoding
  - HTML encoding
  - SQL parameterization
  - JSON escaping

✅ Authentication/authorization
  - Strong cryptography
  - Secure session management
  - Permission checks

✅ Encryption
  - Use modern algorithms
  - Manage keys rigorously
  - Enforce HTTPS

✅ Error handling
  - Never expose detailed information
  - Keep logs on the server only
  - Fail gracefully

✅ Logging
  - Record security events
  - Mask sensitive data
  - Keep an audit trail
*/
```

### Defensive Code for the OWASP Top 10

```javascript
// 1. Preventing Injection
const mysql = require('mysql2/promise');

// ❌ Vulnerable code
const username = req.body.username;
const query = `SELECT * FROM users WHERE username = '${username}'`;
await connection.query(query);

// ✅ Safe code
const query = 'SELECT * FROM users WHERE username = ?';
await connection.query(query, [username]);

// 2. Preventing Broken Authentication
const bcrypt = require('bcrypt');

// ❌ Vulnerable code
const password = req.body.password;
user.password = password;  // Stored in plain text!

// ✅ Safe code
const saltRounds = 12;
const hashedPassword = await bcrypt.hash(password, saltRounds);
user.password = hashedPassword;

// 3. Preventing Sensitive Data Exposure
const crypto = require('crypto');

// ❌ Vulnerable code
const ssn = user.ssn;
console.log('SSN:', ssn);  // Exposed in the logs!

// ✅ Safe code
const encryptSSN = (ssn) => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(
    'aes-256-gcm',
    Buffer.from(process.env.ENCRYPTION_KEY, 'hex'),
    iv
  );
  
  let encrypted = cipher.update(ssn, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  return {
    encrypted,
    iv: iv.toString('hex'),
    authTag: cipher.getAuthTag().toString('hex')
  };
};

// 4. Preventing XML External Entities (XXE)
const libxmljs = require('libxmljs');

// ❌ Vulnerable code
const xml = libxmljs.parseXml(req.body.xml);

// ✅ Safe code
const xml = libxmljs.parseXml(req.body.xml, {
  noent: false,  // Disable entities
  dtdload: false,  // Disable DTD loading
  nocdata: true
});

// 5. Preventing Broken Access Control
const checkPermission = async (req, res, next) => {
  const userId = req.user.id;
  const resourceId = req.params.id;
  
  // Check the resource owner
  const resource = await Resource.findById(resourceId);
  
  if (!resource) {
    return res.status(404).json({ error: 'Resource not found' });
  }
  
  // Allow only the owner or an admin
  if (resource.ownerId !== userId && !req.user.isAdmin) {
    return res.status(403).json({ error: 'Permission denied' });
  }
  
  next();
};

app.delete('/api/resources/:id', authenticateToken, checkPermission, async (req, res) => {
  // Deletion logic...
});

// 6. Preventing Security Misconfiguration
const helmet = require('helmet');

app.use(helmet());  // Sets security headers automatically
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    imgSrc: ["'self'", "data:", "https:"],
    connectSrc: ["'self'"],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: ["'none'"]
  }
}));

// Disable debug mode in production
if (process.env.NODE_ENV === 'production') {
  app.set('view cache', true);
  console.log = () => {};  // Disable console logging
}

// 7. Preventing XSS
const xss = require('xss');

// ❌ Vulnerable code
const comment = req.body.comment;
res.send(`<div>${comment}</div>`);

// ✅ Safe code
const sanitizedComment = xss(comment);
res.send(`<div>${sanitizedComment}</div>`);

// 8. Preventing Insecure Deserialization
// ❌ Vulnerable code (uses eval)
const data = eval(req.body.data);

// ✅ Safe code
try {
  const data = JSON.parse(req.body.data);
} catch (err) {
  return res.status(400).json({ error: 'Invalid data format' });
}

// 9. Preventing Using Components with Known Vulnerabilities
// Add security scripts to package.json
{
  "scripts": {
    "audit": "npm audit --audit-level=high",
    "preinstall": "npm audit"
  }
}

// 10. Insufficient Logging & Monitoring
const winston = require('winston');

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'security.log', level: 'warn' })
  ]
});

// Log every security event
app.use((req, res, next) => {
  if (req.path.includes('/admin') || req.path.includes('/api/sensitive')) {
    logger.warn('Sensitive resource access', {
      userId: req.user?.id,
      ip: req.ip,
      path: req.path,
      method: req.method
    });
  }
  next();
});
```

---

## 5. Phase 4: Testing

### 1) SAST (Static Application Security Testing) ⭐️⭐️⭐️

```bash
# ESLint Security Plugin
npm install --save-dev eslint-plugin-security

# .eslintrc.json
{
  "plugins": ["security"],
  "extends": ["plugin:security/recommended"],
  "rules": {
    "security/detect-object-injection": "error",
    "security/detect-non-literal-regexp": "warn",
    "security/detect-unsafe-regex": "error",
    "security/detect-buffer-noassert": "error",
    "security/detect-child-process": "warn",
    "security/detect-eval-with-expression": "error"
  }
}

# SonarQube
docker run -d --name sonarqube -p 9000:9000 sonarqube:latest

# Semgrep (free SAST)
pip install semgrep
semgrep --config=auto .
```

### 2) DAST (Dynamic Application Security Testing) ⭐️⭐️⭐️

```bash
# OWASP ZAP (free DAST tool)
docker run -v $(pwd):/zap/wrk/:rw -t owasp/zap2docker-stable \
  zap-baseline.py -t http://localhost:3000 -r zap-report.html

# Burp Suite (paid)
# https://portswigger.net/burp

# Nikto (web server scanner)
docker run --rm -it secfigo/nikto:latest -h http://example.com
```

### 3) Penetration Testing

```javascript
// Manual penetration testing checklist

/*
1. Authentication bypass
   - Test default accounts
   - Brute Force
   - SQL Injection in Login

2. Privilege escalation
   - IDOR (Insecure Direct Object Reference)
   - Access to admin features

3. Input validation
   - XSS payloads
   - SQL Injection
   - Command Injection

4. Session management
   - Session hijacking
   - CSRF

5. Business logic
   - Race Condition
   - Price manipulation
   - Unlimited discounts

6. File upload
   - Malicious file uploads
   - Path Traversal

7. API security
   - Rate limiting tests
   - Mass Assignment
   - API key exposure
*/
```

### 4) Security Unit Tests

```javascript
// security.test.js
const request = require('supertest');
const app = require('../app');

describe('Security Tests', () => {
  
  // SQL injection prevention test
  test('should prevent SQL injection', async () => {
    const maliciousInput = "admin' OR '1'='1";
    
    const response = await request(app)
      .post('/api/login')
      .send({ username: maliciousInput, password: 'password' });
    
    expect(response.status).toBe(401);
    expect(response.body.error).toBe('Authentication failed');
  });
  
  // XSS prevention test
  test('should sanitize XSS payload', async () => {
    const xssPayload = '<script>alert("XSS")</script>';
    
    const response = await request(app)
      .post('/api/comments')
      .set('Authorization', `Bearer ${token}`)
      .send({ comment: xssPayload });
    
    expect(response.body.comment).not.toContain('<script>');
  });
  
  // CSRF prevention test
  test('should require CSRF token', async () => {
    const response = await request(app)
      .post('/api/transfer')
      .send({ amount: 1000, to: 'attacker' });
    
    expect(response.status).toBe(403);
  });
  
  // Rate limiting test
  test('should enforce rate limiting', async () => {
    const requests = [];
    
    for (let i = 0; i < 101; i++) {
      requests.push(
        request(app).post('/api/login').send({ username: 'test', password: 'test' })
      );
    }
    
    const responses = await Promise.all(requests);
    const tooManyRequests = responses.filter(r => r.status === 429);
    
    expect(tooManyRequests.length).toBeGreaterThan(0);
  });
  
  // Authorization test
  test('should prevent unauthorized access', async () => {
    const regularUserToken = 'regular_user_token';
    
    const response = await request(app)
      .delete('/api/users/123')
      .set('Authorization', `Bearer ${regularUserToken}`);
    
    expect(response.status).toBe(403);
  });
  
});
```

---

## 6. Phase 5: Deployment

### Securing the CI/CD Pipeline

```yaml
# .github/workflows/secure-deploy.yml
name: Secure Deployment

on:
  push:
    branches: [main]

jobs:
  security-checks:
    runs-on: ubuntu-latest
    
    steps:
      # 1. Check out the code
      - uses: actions/checkout@v3
      
      # 2. Secret scanning
      - name: GitGuardian scan
        uses: GitGuardian/ggshield-action@v1
        env:
          GITGUARDIAN_API_KEY: ${{ secrets.GITGUARDIAN_API_KEY }}
      
      # 3. Dependency scanning
      - name: Run npm audit
        run: |
          npm ci
          npm audit --audit-level=high
      
      # 4. SAST
      - name: Run Semgrep
        run: |
          pip install semgrep
          semgrep --config=auto --error
      
      # 5. Code quality
      - name: SonarCloud Scan
        uses: SonarSource/sonarcloud-github-action@master
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
      
      # 6. Container scanning
      - name: Build Docker image
        run: docker build -t myapp:${{ github.sha }} .
      
      - name: Scan Docker image
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'myapp:${{ github.sha }}'
          severity: 'CRITICAL,HIGH'
      
      # 7. Tests
      - name: Run security tests
        run: npm test -- --testPathPattern=security
      
      # 8. Deploy
      - name: Deploy to production
        if: success()
        run: |
          # Deployment logic...
          echo "Deploying to production"
```

### Secure Deployment Checklist

```javascript
/*
Pre-deployment checklist:

✅ Code security
  - [ ] SAST passed
  - [ ] Security code review done
  - [ ] Vulnerabilities resolved

✅ Dependency security
  - [ ] npm audit passed
  - [ ] Updated to latest versions
  - [ ] Licenses checked

✅ Configuration security
  - [ ] Environment variables validated
  - [ ] Debug mode disabled
  - [ ] Default passwords changed
  - [ ] HTTPS enforced

✅ Infrastructure security
  - [ ] Firewall configured
  - [ ] Least-privilege IAM roles
  - [ ] Backups configured
  - [ ] Monitoring enabled

✅ Testing
  - [ ] Unit tests passed
  - [ ] Integration tests passed
  - [ ] Security tests passed
  - [ ] DAST scan completed

✅ Documentation
  - [ ] Security guide updated
  - [ ] Incident response plan
  - [ ] Rollback plan
*/
```

---

## 7. Phase 6: Operations and Monitoring

### Security Monitoring

```javascript
// Real-time security monitoring
const logger = require('./logger');
const alertService = require('./alert-service');

class SecurityMonitor {
  constructor() {
    this.suspiciousActivities = new Map();
    this.threshold = {
      failedLogins: 5,
      apiCalls: 100,
      largeDataAccess: 1000
    };
  }
  
  // Monitor failed logins
  trackFailedLogin(userId, ip) {
    const key = `${userId}:${ip}`;
    const count = (this.suspiciousActivities.get(key) || 0) + 1;
    
    this.suspiciousActivities.set(key, count);
    
    if (count >= this.threshold.failedLogins) {
      alertService.sendAlert(
        '🚨 Security alert: repeated login failures',
        `User ${userId} failed to log in ${count} times from ${ip}`
      );
      
      // Temporarily lock the account
      this.lockAccount(userId);
    }
  }
  
  // Detect abnormal API calls
  async detectAnomalies(userId, endpoint) {
    const recentCalls = await this.getRecentAPICalls(userId, endpoint);
    
    if (recentCalls.length > this.threshold.apiCalls) {
      logger.warn('Anomalous API activity detected', {
        userId,
        endpoint,
        callCount: recentCalls.length
      });
      
      // Tighten rate limiting
      this.enforceStrictRateLimit(userId);
    }
  }
  
  // Monitor bulk data access
  trackDataAccess(userId, recordCount) {
    if (recordCount > this.threshold.largeDataAccess) {
      logger.warn('Large data access detected', {
        userId,
        recordCount,
        timestamp: new Date()
      });
      
      alertService.sendAlert(
        '⚠️ Bulk data access',
        `User ${userId} accessed ${recordCount} records`
      );
    }
  }
}

module.exports = new SecurityMonitor();
```

### Incident Response Plan

```markdown
# Security Incident Response Plan

## 1. Detection
- Alerts from monitoring systems
- User reports
- Security scan results

## 2. Analysis
- Determine the scope of impact
- Identify the attack vector
- Assess the extent of the damage

## 3. Containment
- Block the attack
- Isolate affected systems
- Prevent further damage

## 4. Eradication
- Patch vulnerabilities
- Remove malware
- Remove backdoors

## 5. Recovery
- Restore systems
- Recover data
- Resume service

## 6. Lessons Learned
- Root cause analysis
- Evaluate the response
- Plan improvements

## Emergency Contacts
- Security Team: security@example.com
- On-call Engineer: +82-10-1234-5678
- CEO: ceo@example.com
```

---

## Best Practices Summary

### Development Process
- ✅ Integrate security into every phase
- ✅ Shift Left (validate security early)
- ✅ Automated security testing
- ✅ Regular code reviews
- ✅ Security training

### Tooling
- ✅ SAST: SonarQube, Semgrep
- ✅ DAST: OWASP ZAP, Burp Suite
- ✅ SCA: Snyk, Dependabot
- ✅ Secret Scanning: GitGuardian

### Culture
- ✅ Security is everyone's responsibility
- ✅ Learn from failures
- ✅ Transparent reporting
- ✅ Continuous improvement

---

## Conclusion

SSDLC isn't just a process — it's an organization's security culture. When you build security in from the start instead of adding it later, you end up with software that's safer and more trustworthy.

**Core principles:**
1. **Shift Left**: validate security as early as possible
2. **Automation**: automate repetitive work
3. **Continuous**: security is ongoing, not a one-time task
4. **Culture**: make every team member security-aware

Security is a journey, not a destination!
