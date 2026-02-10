---
title: SSDLC - 보안 개발 생명주기 가이드
published: false
description: Secure Software Development Lifecycle. 요구사항부터 배포까지 전 단계의 보안. SAST, DAST, Code Review, Threat Modeling을 상세히 설명합니다.
tags: security, ssdlc, devops, sast, dast, code-review
cover_image: https://example.com/your-cover-image.jpg
---

# SSDLC - 보안 개발 생명주기 가이드

SSDLC(Secure Software Development Lifecycle)는 소프트웨어 개발의 모든 단계에 보안을 통합하는 접근 방식입니다. 보안을 나중에 추가하는 것이 아니라 처음부터 내재화합니다.

---

## 1. SSDLC 개요 ⭐️⭐️⭐️

### 전통적 SDLC vs SSDLC

```javascript
// ❌ 전통적 SDLC (보안은 나중에)
계획 → 설계 → 개발 → 테스트 → 배포 → [보안 검토] ← 너무 늦음!

// ✅ SSDLC (보안이 각 단계에 통합)
[보안 요구사항] → [보안 설계] → [안전한 코딩] → [보안 테스트] → [보안 배포] → [모니터링]
```

### SSDLC의 이점

```javascript
/*
1. 조기 취약점 발견
   - 개발 초기에 발견하면 수정 비용 100배 저렴
   
2. 보안 문화 구축
   - 개발자가 보안 의식 갖춤
   
3. 컴플라이언스 준수
   - GDPR, PCI-DSS 등 규정 만족
   
4. 고객 신뢰 증대
   - 보안 사고 예방
   
5. 비용 절감
   - 사후 대응보다 사전 예방이 저렴
*/
```

---

## 2. Phase 1: 요구사항 수집 및 계획

### 보안 요구사항 정의

```markdown
## 보안 요구사항 체크리스트

### 인증 및 인가
- [ ] 다단계 인증 (MFA) 지원
- [ ] 역할 기반 접근 제어 (RBAC)
- [ ] 세션 타임아웃 (30분)
- [ ] 비밀번호 정책 (최소 12자, 특수문자 포함)

### 데이터 보호
- [ ] 전송 중 암호화 (TLS 1.3)
- [ ] 저장 시 암호화 (AES-256)
- [ ] 민감 정보 마스킹
- [ ] 데이터 백업 및 복구

### 로깅 및 모니터링
- [ ] 보안 이벤트 로깅
- [ ] 실시간 침입 탐지
- [ ] 감사 추적 (Audit Trail)

### 컴플라이언스
- [ ] GDPR 준수
- [ ] PCI-DSS 준수 (결제 시스템)
- [ ] 개인정보 처리방침

### 인프라 보안
- [ ] WAF (Web Application Firewall)
- [ ] DDoS 방어
- [ ] 정기적 취약점 스캔
```

### 위협 모델링 (Threat Modeling)

```javascript
// STRIDE 모델

/*
S - Spoofing (스푸핑)
  위협: 가짜 사용자로 위장
  대응: 강력한 인증, MFA

T - Tampering (변조)
  위협: 데이터 무단 수정
  대응: 입력 검증, 무결성 검증

R - Repudiation (부인)
  위협: 행위 부인
  대응: 감사 로그, 디지털 서명

I - Information Disclosure (정보 노출)
  위협: 민감 정보 유출
  대응: 암호화, 접근 제어

D - Denial of Service (서비스 거부)
  위협: 서비스 마비
  대응: Rate Limiting, CDN

E - Elevation of Privilege (권한 상승)
  위협: 관리자 권한 탈취
  대응: 최소 권한 원칙, RBAC
*/
```

### Attack Tree 예제

```javascript
// 공격 시나리오: 사용자 계정 탈취

/*
[목표: 사용자 계정 탈취]
    │
    ├─ [AND] 비밀번호 획득
    │   ├─ [OR] Brute Force
    │   │   └─ 대응: Rate Limiting, CAPTCHA
    │   ├─ [OR] Phishing
    │   │   └─ 대응: 보안 교육, 2FA
    │   └─ [OR] SQL Injection
    │       └─ 대응: Prepared Statements
    │
    └─ [AND] 세션 탈취
        ├─ [OR] XSS
        │   └─ 대응: CSP, Input Sanitization
        └─ [OR] CSRF
            └─ 대응: CSRF Token
*/
```

---

## 3. Phase 2: 설계

### 보안 아키텍처 설계 원칙

```javascript
/*
1. 심층 방어 (Defense in Depth)
   - 여러 계층의 보안 제어
   
2. 최소 권한 (Least Privilege)
   - 필요한 최소한의 권한만 부여
   
3. 실패 시 안전 (Fail Secure)
   - 오류 발생 시 안전한 상태로
   
4. 기본적으로 거부 (Deny by Default)
   - 명시적으로 허용한 것만 접근
   
5. 완전한 중재 (Complete Mediation)
   - 모든 접근 검증
   
6. 개방형 설계 (Open Design)
   - 보안은 비밀이 아닌 설계에 의존
*/
```

### 보안 설계 패턴

```javascript
// 1. Secure by Default
class UserService {
  constructor() {
    // 기본값은 가장 제한적으로
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
      mfaEnabled: true,  // 기본적으로 MFA 활성화
      sessionTimeout: 30 * 60 * 1000  // 30분
    };
  }
}

// 2. Input Validation Layer
class ValidationLayer {
  static validateInput(data, schema) {
    // 모든 입력은 검증 계층을 통과해야 함
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
    // 환경 변수에서 안전하게 로드
    this.jwtSecret = process.env.JWT_SECRET;
    this.encryptionKey = process.env.ENCRYPTION_KEY;
    
    if (!this.jwtSecret || !this.encryptionKey) {
      throw new Error('필수 보안 설정이 누락되었습니다');
    }
    
    // 프로덕션에서는 디버그 모드 비활성화
    this.debugMode = process.env.NODE_ENV !== 'production';
  }
}
```

---

## 4. Phase 3: 개발 (안전한 코딩)

### Secure Coding 체크리스트

```javascript
/*
✅ 입력 검증
  - 모든 입력 검증
  - 화이트리스트 방식 선호
  - 정규표현식 주의

✅ 출력 인코딩
  - HTML 인코딩
  - SQL 파라미터화
  - JSON 이스케이프

✅ 인증/인가
  - 강력한 암호화
  - 안전한 세션 관리
  - 권한 검증

✅ 암호화
  - 최신 알고리즘 사용
  - 키 관리 철저
  - HTTPS 강제

✅ 에러 처리
  - 상세 정보 노출 금지
  - 로그는 서버에만
  - 우아한 실패

✅ 로깅
  - 보안 이벤트 기록
  - 민감 정보 마스킹
  - 감사 추적
*/
```

### OWASP Top 10 방어 코드

```javascript
// 1. Injection 방어
const mysql = require('mysql2/promise');

// ❌ 취약한 코드
const username = req.body.username;
const query = `SELECT * FROM users WHERE username = '${username}'`;
await connection.query(query);

// ✅ 안전한 코드
const query = 'SELECT * FROM users WHERE username = ?';
await connection.query(query, [username]);

// 2. Broken Authentication 방어
const bcrypt = require('bcrypt');

// ❌ 취약한 코드
const password = req.body.password;
user.password = password;  // 평문 저장!

// ✅ 안전한 코드
const saltRounds = 12;
const hashedPassword = await bcrypt.hash(password, saltRounds);
user.password = hashedPassword;

// 3. Sensitive Data Exposure 방어
const crypto = require('crypto');

// ❌ 취약한 코드
const ssn = user.ssn;
console.log('SSN:', ssn);  // 로그에 노출!

// ✅ 안전한 코드
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

// 4. XML External Entities (XXE) 방어
const libxmljs = require('libxmljs');

// ❌ 취약한 코드
const xml = libxmljs.parseXml(req.body.xml);

// ✅ 안전한 코드
const xml = libxmljs.parseXml(req.body.xml, {
  noent: false,  // Entity 비활성화
  dtdload: false,  // DTD 로딩 비활성화
  nocdata: true
});

// 5. Broken Access Control 방어
const checkPermission = async (req, res, next) => {
  const userId = req.user.id;
  const resourceId = req.params.id;
  
  // 리소스 소유자 확인
  const resource = await Resource.findById(resourceId);
  
  if (!resource) {
    return res.status(404).json({ error: '리소스를 찾을 수 없습니다' });
  }
  
  // 소유자이거나 관리자인 경우만 허용
  if (resource.ownerId !== userId && !req.user.isAdmin) {
    return res.status(403).json({ error: '권한이 없습니다' });
  }
  
  next();
};

app.delete('/api/resources/:id', authenticateToken, checkPermission, async (req, res) => {
  // 삭제 로직...
});

// 6. Security Misconfiguration 방어
const helmet = require('helmet');

app.use(helmet());  // 보안 헤더 자동 설정
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

// 프로덕션에서 디버그 모드 비활성화
if (process.env.NODE_ENV === 'production') {
  app.set('view cache', true);
  console.log = () => {};  // 콘솔 로그 비활성화
}

// 7. XSS 방어
const xss = require('xss');

// ❌ 취약한 코드
const comment = req.body.comment;
res.send(`<div>${comment}</div>`);

// ✅ 안전한 코드
const sanitizedComment = xss(comment);
res.send(`<div>${sanitizedComment}</div>`);

// 8. Insecure Deserialization 방어
// ❌ 취약한 코드 (eval 사용)
const data = eval(req.body.data);

// ✅ 안전한 코드
try {
  const data = JSON.parse(req.body.data);
} catch (err) {
  return res.status(400).json({ error: '잘못된 데이터 형식' });
}

// 9. Using Components with Known Vulnerabilities 방어
// package.json에 보안 스크립트 추가
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

// 모든 보안 이벤트 로깅
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

## 5. Phase 4: 테스트

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

# Semgrep (무료 SAST)
npm install -g @semgrep/cli
semgrep --config=auto .
```

### 2) DAST (Dynamic Application Security Testing) ⭐️⭐️⭐️

```bash
# OWASP ZAP (무료 DAST 도구)
docker run -v $(pwd):/zap/wrk/:rw -t owasp/zap2docker-stable \
  zap-baseline.py -t http://localhost:3000 -r zap-report.html

# Burp Suite (유료)
# https://portswigger.net/burp

# Nikto (웹 서버 스캔)
docker run --rm -it secfigo/nikto:latest -h http://example.com
```

### 3) 침투 테스트 (Penetration Testing)

```javascript
// 수동 침투 테스트 체크리스트

/*
1. 인증 우회
   - 기본 계정 테스트
   - Brute Force
   - SQL Injection in Login

2. 권한 상승
   - IDOR (Insecure Direct Object Reference)
   - 관리자 기능 접근

3. 입력 검증
   - XSS 페이로드
   - SQL Injection
   - Command Injection

4. 세션 관리
   - 세션 하이재킹
   - CSRF

5. 비즈니스 로직
   - Race Condition
   - 가격 조작
   - 무한 할인

6. 파일 업로드
   - 악성 파일 업로드
   - Path Traversal

7. API 보안
   - Rate Limiting 테스트
   - Mass Assignment
   - API Key 노출
*/
```

### 4) 보안 단위 테스트

```javascript
// security.test.js
const request = require('supertest');
const app = require('../app');

describe('Security Tests', () => {
  
  // SQL Injection 방어 테스트
  test('should prevent SQL injection', async () => {
    const maliciousInput = "admin' OR '1'='1";
    
    const response = await request(app)
      .post('/api/login')
      .send({ username: maliciousInput, password: 'password' });
    
    expect(response.status).toBe(401);
    expect(response.body.error).toBe('인증 실패');
  });
  
  // XSS 방어 테스트
  test('should sanitize XSS payload', async () => {
    const xssPayload = '<script>alert("XSS")</script>';
    
    const response = await request(app)
      .post('/api/comments')
      .set('Authorization', `Bearer ${token}`)
      .send({ comment: xssPayload });
    
    expect(response.body.comment).not.toContain('<script>');
  });
  
  // CSRF 방어 테스트
  test('should require CSRF token', async () => {
    const response = await request(app)
      .post('/api/transfer')
      .send({ amount: 1000, to: 'attacker' });
    
    expect(response.status).toBe(403);
  });
  
  // Rate Limiting 테스트
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
  
  // 권한 검증 테스트
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

## 6. Phase 5: 배포

### CI/CD 파이프라인 보안

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
      # 1. 코드 체크아웃
      - uses: actions/checkout@v3
      
      # 2. 시크릿 스캔
      - name: GitGuardian scan
        uses: GitGuardian/ggshield-action@v1
        env:
          GITGUARDIAN_API_KEY: ${{ secrets.GITGUARDIAN_API_KEY }}
      
      # 3. 의존성 스캔
      - name: Run npm audit
        run: |
          npm ci
          npm audit --audit-level=high
      
      # 4. SAST
      - name: Run Semgrep
        run: |
          pip install semgrep
          semgrep --config=auto --error
      
      # 5. 코드 품질
      - name: SonarCloud Scan
        uses: SonarSource/sonarcloud-github-action@master
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
      
      # 6. 컨테이너 스캔
      - name: Build Docker image
        run: docker build -t myapp:${{ github.sha }} .
      
      - name: Scan Docker image
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: 'myapp:${{ github.sha }}'
          severity: 'CRITICAL,HIGH'
      
      # 7. 테스트
      - name: Run security tests
        run: npm test -- --testPathPattern=security
      
      # 8. 배포
      - name: Deploy to production
        if: success()
        run: |
          # 배포 로직...
          echo "Deploying to production"
```

### 보안 배포 체크리스트

```javascript
/*
배포 전 체크리스트:

✅ 코드 보안
  - [ ] SAST 통과
  - [ ] 보안 코드 리뷰 완료
  - [ ] 취약점 해결

✅ 의존성 보안
  - [ ] npm audit 통과
  - [ ] 최신 버전 업데이트
  - [ ] 라이선스 확인

✅ 설정 보안
  - [ ] 환경 변수 검증
  - [ ] 디버그 모드 비활성화
  - [ ] 기본 비밀번호 변경
  - [ ] HTTPS 강제

✅ 인프라 보안
  - [ ] 방화벽 설정
  - [ ] 최소 권한 IAM 역할
  - [ ] 백업 설정
  - [ ] 모니터링 활성화

✅ 테스트
  - [ ] 단위 테스트 통과
  - [ ] 통합 테스트 통과
  - [ ] 보안 테스트 통과
  - [ ] DAST 스캔 완료

✅ 문서화
  - [ ] 보안 가이드 업데이트
  - [ ] 인시던트 대응 계획
  - [ ] 롤백 계획
*/
```

---

## 7. Phase 6: 운영 및 모니터링

### 보안 모니터링

```javascript
// 실시간 보안 모니터링
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
  
  // 로그인 실패 모니터링
  trackFailedLogin(userId, ip) {
    const key = `${userId}:${ip}`;
    const count = (this.suspiciousActivities.get(key) || 0) + 1;
    
    this.suspiciousActivities.set(key, count);
    
    if (count >= this.threshold.failedLogins) {
      alertService.sendAlert(
        '🚨 보안 경고: 반복된 로그인 실패',
        `사용자 ${userId}가 ${ip}에서 ${count}회 로그인 실패`
      );
      
      // 계정 임시 잠금
      this.lockAccount(userId);
    }
  }
  
  // 비정상적인 API 호출 탐지
  async detectAnomalies(userId, endpoint) {
    const recentCalls = await this.getRecentAPICalls(userId, endpoint);
    
    if (recentCalls.length > this.threshold.apiCalls) {
      logger.warn('Anomalous API activity detected', {
        userId,
        endpoint,
        callCount: recentCalls.length
      });
      
      // Rate Limiting 강화
      this.enforceStrictRateLimit(userId);
    }
  }
  
  // 대량 데이터 접근 모니터링
  trackDataAccess(userId, recordCount) {
    if (recordCount > this.threshold.largeDataAccess) {
      logger.warn('Large data access detected', {
        userId,
        recordCount,
        timestamp: new Date()
      });
      
      alertService.sendAlert(
        '⚠️ 대량 데이터 접근',
        `사용자 ${userId}가 ${recordCount}건의 데이터 접근`
      );
    }
  }
}

module.exports = new SecurityMonitor();
```

### 인시던트 대응 계획

```markdown
# 보안 인시던트 대응 계획 (Incident Response Plan)

## 1. 탐지 (Detection)
- 모니터링 시스템 알림
- 사용자 신고
- 보안 스캔 결과

## 2. 분석 (Analysis)
- 영향 범위 파악
- 공격 벡터 식별
- 피해 규모 평가

## 3. 격리 (Containment)
- 공격 차단
- 영향받은 시스템 격리
- 추가 피해 방지

## 4. 제거 (Eradication)
- 취약점 패치
- 악성 코드 제거
- 백도어 제거

## 5. 복구 (Recovery)
- 시스템 복원
- 데이터 복구
- 서비스 재개

## 6. 사후 분석 (Lessons Learned)
- 원인 분석
- 대응 평가
- 개선 계획 수립

## 비상 연락망
- Security Team: security@example.com
- On-call Engineer: +82-10-1234-5678
- CEO: ceo@example.com
```

---

## 베스트 프랙티스 요약

### 개발 프로세스
- ✅ 모든 단계에 보안 통합
- ✅ Shift Left (조기 보안 검증)
- ✅ 자동화된 보안 테스트
- ✅ 정기적인 코드 리뷰
- ✅ 보안 교육

### 도구 활용
- ✅ SAST: SonarQube, Semgrep
- ✅ DAST: OWASP ZAP, Burp Suite
- ✅ SCA: Snyk, Dependabot
- ✅ Secret Scanning: GitGuardian

### 문화
- ✅ 보안은 모두의 책임
- ✅ 실패에서 배우기
- ✅ 투명한 보고
- ✅ 지속적인 개선

---

## 결론

SSDLC는 단순한 프로세스가 아니라 조직의 보안 문화입니다. 보안을 나중에 추가하는 것이 아니라 처음부터 내재화하면 더 안전하고 신뢰할 수 있는 소프트웨어를 만들 수 있습니다.

**핵심 원칙:**
1. **Shift Left**: 가능한 한 일찍 보안 검증
2. **Automation**: 반복 작업은 자동화
3. **Continuous**: 한 번이 아닌 지속적인 보안
4. **Culture**: 보안 의식을 모든 팀원에게

보안은 목적지가 아닌 여정입니다!
