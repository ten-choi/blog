---
title: Authentication & Authorization - 완벽 가이드
published: false
description: 사용자 인증과 권한 관리의 모든 것. JWT, OAuth 2.0, Session, MFA, RBAC, ABAC 등 실전 구현 방법을 상세히 설명합니다.
tags: security, authentication, authorization, jwt, oauth
cover_image: https://example.com/your-cover-image.jpg
---

# Authentication & Authorization - 완벽 가이드

인증(Authentication)과 인가(Authorization)는 보안의 최전선입니다. 이 가이드에서는 현대 웹 애플리케이션에서 사용자를 안전하게 식별하고 권한을 관리하는 방법을 다룹니다.

---

## 1. 인증(Authentication) vs 인가(Authorization)

### 개념

**인증(Authentication)**: "당신은 누구인가?"
- 사용자의 신원을 확인하는 과정
- 로그인, 생체 인증, 토큰 검증 등

**인가(Authorization)**: "당신이 이 작업을 할 권한이 있는가?"
- 인증된 사용자의 권한을 확인하는 과정
- 역할 기반 접근 제어, 리소스 소유권 검증 등

### 실생활 예시

```
공항 보안 검색대:
1. 인증: 신분증 확인 (당신이 티켓의 주인인지 확인)
2. 인가: 탑승권 확인 (당신이 이 비행기에 탑승할 권한이 있는지 확인)
```

---

## 2. JWT (JSON Web Token) ⭐️⭐️⭐️

### 개념

JWT는 JSON 객체를 사용하여 정보를 안전하게 전송하기 위한 토큰 기반 인증 방식입니다.

**구조**: `Header.Payload.Signature`

```javascript
// JWT 예시
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJ1c2VySWQiOiIxMjM0NSIsInJvbGUiOiJ1c2VyIn0.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### 구현 방법

**토큰 생성 및 검증**

```javascript
const jwt = require('jsonwebtoken');

// 1. 로그인 시 토큰 발급
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  // 사용자 인증
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: '이메일 또는 비밀번호가 잘못되었습니다' });
  }
  
  // JWT 토큰 생성
  const accessToken = jwt.sign(
    { 
      userId: user.id, 
      email: user.email,
      role: user.role 
    },
    process.env.JWT_SECRET,
    { expiresIn: '15m' }
  );
  
  const refreshToken = jwt.sign(
    { userId: user.id },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: '7d' }
  );
  
  // Refresh Token은 DB에 저장
  await user.update({ refreshToken });
  
  res.json({ 
    accessToken,
    refreshToken,
    user: { id: user.id, email: user.email, role: user.role }
  });
});

// 2. 토큰 검증 미들웨어
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
  
  if (!token) {
    return res.status(401).json({ error: '인증 토큰이 필요합니다' });
  }
  
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: '토큰이 만료되었습니다' });
      }
      return res.status(403).json({ error: '유효하지 않은 토큰입니다' });
    }
    
    req.user = decoded;
    next();
  });
}

// 3. Refresh Token으로 새 Access Token 발급
app.post('/api/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  
  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token이 필요합니다' });
  }
  
  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(403).json({ error: '유효하지 않은 refresh token입니다' });
    }
    
    const newAccessToken = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );
    
    res.json({ accessToken: newAccessToken });
  } catch (err) {
    return res.status(403).json({ error: 'Refresh token이 유효하지 않습니다' });
  }
});

// 4. 로그아웃 (Refresh Token 무효화)
app.post('/api/logout', authenticateToken, async (req, res) => {
  await User.findByIdAndUpdate(req.user.userId, { refreshToken: null });
  res.json({ message: '로그아웃 되었습니다' });
});

// 보호된 라우트 사용 예
app.get('/api/profile', authenticateToken, (req, res) => {
  res.json({ 
    userId: req.user.userId,
    email: req.user.email,
    role: req.user.role
  });
});
```

### 베스트 프랙티스

- **짧은 만료 시간**: Access Token은 15분~1시간
- **Refresh Token 사용**: 장기간 인증 유지
- **안전한 Secret**: 최소 256비트 랜덤 문자열
- **HTTPS 필수**: 토큰은 항상 HTTPS로만 전송
- **민감 정보 제외**: Payload에 비밀번호 등 넣지 않기

---

## 3. OAuth 2.0 & Social Login ⭐️⭐️⭐️

### 개념

OAuth 2.0은 제3자 애플리케이션이 사용자의 리소스에 접근할 수 있도록 권한을 위임하는 표준 프로토콜입니다.

### Google OAuth 2.0 구현

```javascript
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

// 1. Passport 설정
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      // 기존 사용자 찾기
      let user = await User.findOne({ googleId: profile.id });
      
      if (!user) {
        // 새 사용자 생성
        user = await User.create({
          googleId: profile.id,
          email: profile.emails[0].value,
          name: profile.displayName,
          avatar: profile.photos[0].value
        });
      }
      
      return done(null, user);
    } catch (err) {
      return done(err, null);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

// 2. 라우트 설정
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { 
    failureRedirect: '/login',
    session: false // JWT를 사용하는 경우
  }),
  (req, res) => {
    // JWT 토큰 발급
    const token = jwt.sign(
      { userId: req.user.id, email: req.user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    // 클라이언트로 리다이렉트 (토큰 포함)
    res.redirect(`${process.env.CLIENT_URL}/auth/callback?token=${token}`);
  }
);
```

---

## 4. Session 기반 인증 ⭐️⭐️

### 개념

서버에 사용자 정보를 저장하고 클라이언트에게는 Session ID만 전달하는 방식입니다.

### 구현 방법

```javascript
const session = require('express-session');
const RedisStore = require('connect-redis')(session);
const redis = require('redis');

// Redis 클라이언트 생성
const redisClient = redis.createClient({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT
});

// Session 설정
app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // HTTPS에서만
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7일
    sameSite: 'strict'
  }
}));

// 로그인
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: '인증 실패' });
  }
  
  // 세션에 사용자 정보 저장
  req.session.userId = user.id;
  req.session.email = user.email;
  req.session.role = user.role;
  
  res.json({ message: '로그인 성공', user: { id: user.id, email: user.email } });
});

// 인증 확인 미들웨어
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: '로그인이 필요합니다' });
  }
  next();
}

// 로그아웃
app.post('/api/logout', requireAuth, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: '로그아웃 실패' });
    }
    res.clearCookie('connect.sid');
    res.json({ message: '로그아웃 성공' });
  });
});
```

### JWT vs Session 비교

| 특징 | JWT | Session |
|------|-----|---------|
| 저장 위치 | 클라이언트 | 서버 (Redis/DB) |
| Stateless | O | X |
| 확장성 | 좋음 | 보통 |
| 토큰 무효화 | 어려움 | 쉬움 |
| 크기 | 크다 | 작다 (Session ID만) |
| 적합한 경우 | 마이크로서비스, SPA | 전통적인 웹앱 |

---

## 5. 다중 인증 (MFA/2FA) ⭐️⭐️⭐️

### 개념

비밀번호 외에 추가적인 인증 요소를 요구하여 보안을 강화하는 방식입니다.

### TOTP (Time-based One-Time Password) 구현

```javascript
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

// 1. MFA 설정 시작
app.post('/api/mfa/setup', authenticateToken, async (req, res) => {
  const user = await User.findById(req.user.userId);
  
  // TOTP Secret 생성
  const secret = speakeasy.generateSecret({
    name: `MyApp (${user.email})`,
    issuer: 'MyApp'
  });
  
  // 임시로 저장 (확인 후 정식 저장)
  user.tempMfaSecret = secret.base32;
  await user.save();
  
  // QR 코드 생성
  const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
  
  res.json({
    secret: secret.base32,
    qrCode: qrCodeUrl
  });
});

// 2. MFA 설정 확인
app.post('/api/mfa/verify-setup', authenticateToken, async (req, res) => {
  const { token } = req.body;
  const user = await User.findById(req.user.userId);
  
  // 사용자가 입력한 코드 검증
  const verified = speakeasy.totp.verify({
    secret: user.tempMfaSecret,
    encoding: 'base32',
    token,
    window: 2 // 시간 오차 허용
  });
  
  if (verified) {
    user.mfaSecret = user.tempMfaSecret;
    user.mfaEnabled = true;
    user.tempMfaSecret = null;
    await user.save();
    
    res.json({ message: 'MFA가 활성화되었습니다' });
  } else {
    res.status(400).json({ error: '유효하지 않은 코드입니다' });
  }
});

// 3. 로그인 시 MFA 검증
app.post('/api/login', async (req, res) => {
  const { email, password, mfaToken } = req.body;
  
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: '인증 실패' });
  }
  
  // MFA가 활성화된 경우
  if (user.mfaEnabled) {
    if (!mfaToken) {
      return res.status(200).json({ 
        requireMfa: true,
        message: 'MFA 코드를 입력해주세요'
      });
    }
    
    // MFA 코드 검증
    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token: mfaToken,
      window: 2
    });
    
    if (!verified) {
      return res.status(401).json({ error: '유효하지 않은 MFA 코드입니다' });
    }
  }
  
  // JWT 발급
  const token = jwt.sign(
    { userId: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
  
  res.json({ token });
});
```

---

## 6. Role-Based Access Control (RBAC) ⭐️⭐️⭐️

### 개념

사용자에게 역할(Role)을 할당하고, 각 역할마다 권한을 부여하는 방식입니다.

### 구현 방법

```javascript
// 역할 및 권한 정의
const ROLES = {
  ADMIN: 'admin',
  MANAGER: 'manager',
  USER: 'user',
  GUEST: 'guest'
};

const PERMISSIONS = {
  [ROLES.ADMIN]: ['read', 'write', 'delete', 'manage_users'],
  [ROLES.MANAGER]: ['read', 'write', 'delete'],
  [ROLES.USER]: ['read', 'write'],
  [ROLES.GUEST]: ['read']
};

// 권한 확인 미들웨어
function requirePermission(permission) {
  return (req, res, next) => {
    const userRole = req.user.role;
    const userPermissions = PERMISSIONS[userRole] || [];
    
    if (!userPermissions.includes(permission)) {
      return res.status(403).json({ 
        error: '이 작업을 수행할 권한이 없습니다',
        required: permission,
        userRole
      });
    }
    
    next();
  };
}

// 역할 확인 미들웨어
function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ 
        error: '접근 권한이 없습니다',
        requiredRoles: roles,
        userRole: req.user.role
      });
    }
    next();
  };
}

// 사용 예
app.delete('/api/users/:id', 
  authenticateToken,
  requirePermission('delete'),
  async (req, res) => {
    // 삭제 로직
  }
);

app.get('/api/admin/dashboard',
  authenticateToken,
  requireRole(ROLES.ADMIN, ROLES.MANAGER),
  (req, res) => {
    res.json({ message: 'Admin Dashboard' });
  }
);
```

---

## 7. Attribute-Based Access Control (ABAC) ⭐️⭐️

### 개념

사용자 속성, 리소스 속성, 환경 속성 등을 기반으로 동적으로 권한을 결정하는 방식입니다.

### 구현 방법

```javascript
// 리소스 소유권 검증
function checkOwnership(req, res, next) {
  const resourceId = req.params.id;
  const userId = req.user.userId;
  
  db.documents.findById(resourceId).then(document => {
    // 소유자이거나 관리자인 경우 허용
    if (document.ownerId === userId || req.user.role === 'admin') {
      req.document = document;
      return next();
    }
    
    res.status(403).json({ error: '이 문서에 접근할 권한이 없습니다' });
  });
}

// 조건부 권한 검증
function checkDocumentAccess(req, res, next) {
  const document = req.document;
  const user = req.user;
  
  // 공개 문서는 모두 접근 가능
  if (document.visibility === 'public') {
    return next();
  }
  
  // 비공개 문서는 소유자만
  if (document.visibility === 'private' && document.ownerId === user.userId) {
    return next();
  }
  
  // 팀 문서는 같은 팀 멤버만
  if (document.visibility === 'team' && document.teamId === user.teamId) {
    return next();
  }
  
  res.status(403).json({ error: '접근 권한이 없습니다' });
}

// 사용 예
app.get('/api/documents/:id',
  authenticateToken,
  checkOwnership,
  checkDocumentAccess,
  (req, res) => {
    res.json(req.document);
  }
);
```

---

## 8. 비밀번호 보안 ⭐️⭐️⭐️

### 비밀번호 해싱

```javascript
const bcrypt = require('bcrypt');
const argon2 = require('argon2');

// bcrypt 사용 (권장)
async function hashPassword(password) {
  const saltRounds = 12; // 높을수록 보안 강화, 느림
  return await bcrypt.hash(password, saltRounds);
}

async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

// Argon2 사용 (더 강력)
async function hashPasswordArgon2(password) {
  return await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 2 ** 16, // 64MB
    timeCost: 3,
    parallelism: 1
  });
}

async function verifyPasswordArgon2(password, hash) {
  return await argon2.verify(hash, password);
}

// 회원가입
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  
  // 비밀번호 강도 검증
  if (password.length < 8) {
    return res.status(400).json({ error: '비밀번호는 최소 8자 이상이어야 합니다' });
  }
  
  const passwordHash = await hashPassword(password);
  
  const user = await User.create({
    email,
    passwordHash
  });
  
  res.status(201).json({ message: '회원가입 성공', userId: user.id });
});
```

### 비밀번호 정책

```javascript
const passwordValidator = require('password-validator');

const schema = new passwordValidator();

schema
  .is().min(8)                                    // 최소 8자
  .is().max(100)                                  // 최대 100자
  .has().uppercase()                              // 대문자 포함
  .has().lowercase()                              // 소문자 포함
  .has().digits(1)                                // 숫자 1개 이상
  .has().symbols()                                // 특수문자 포함
  .has().not().spaces()                           // 공백 불가
  .is().not().oneOf(['Password123', 'Admin123']); // 흔한 비밀번호 금지

function validatePassword(password) {
  const result = schema.validate(password, { details: true });
  
  if (result === true) {
    return { valid: true };
  }
  
  return { 
    valid: false, 
    errors: result.map(err => err.message)
  };
}
```

---

## 9. Account Security

### Brute Force 방어

```javascript
const rateLimit = require('express-rate-limit');

// 로그인 시도 제한
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15분
  max: 5, // 최대 5회 시도
  message: '너무 많은 로그인 시도가 있었습니다. 15분 후 다시 시도해주세요.',
  standardHeaders: true,
  legacyHeaders: false
});

app.post('/api/login', loginLimiter, async (req, res) => {
  // 로그인 로직
});

// IP별 로그인 실패 추적
const loginAttempts = new Map();

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const ip = req.ip;
  const key = `${ip}:${email}`;
  
  // 실패 횟수 확인
  const attempts = loginAttempts.get(key) || 0;
  
  if (attempts >= 5) {
    return res.status(429).json({ 
      error: '계정이 일시적으로 잠겼습니다. 15분 후 다시 시도해주세요.' 
    });
  }
  
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    // 실패 횟수 증가
    loginAttempts.set(key, attempts + 1);
    
    // 15분 후 자동 삭제
    setTimeout(() => loginAttempts.delete(key), 15 * 60 * 1000);
    
    return res.status(401).json({ error: '인증 실패' });
  }
  
  // 성공 시 실패 횟수 초기화
  loginAttempts.delete(key);
  
  // 토큰 발급
  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});
```

### Account Lockout

```javascript
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  const user = await User.findOne({ email });
  
  // 계정 잠금 확인
  if (user && user.lockedUntil && user.lockedUntil > new Date()) {
    const remainingTime = Math.ceil((user.lockedUntil - new Date()) / 1000 / 60);
    return res.status(403).json({ 
      error: `계정이 잠겼습니다. ${remainingTime}분 후 다시 시도해주세요.` 
    });
  }
  
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    if (user) {
      user.loginAttempts += 1;
      
      // 5회 실패 시 30분 잠금
      if (user.loginAttempts >= 5) {
        user.lockedUntil = new Date(Date.now() + 30 * 60 * 1000);
        await user.save();
        return res.status(403).json({ error: '5회 실패로 계정이 30분간 잠겼습니다.' });
      }
      
      await user.save();
    }
    
    return res.status(401).json({ error: '인증 실패' });
  }
  
  // 로그인 성공 시 초기화
  user.loginAttempts = 0;
  user.lockedUntil = null;
  user.lastLoginAt = new Date();
  await user.save();
  
  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});
```

---

## 베스트 프랙티스 요약

### 인증
- ✅ 비밀번호는 bcrypt/Argon2로 해싱
- ✅ JWT는 15분~1시간 짧은 만료 시간
- ✅ Refresh Token으로 장기 인증 유지
- ✅ HTTPS에서만 토큰 전송
- ✅ MFA 활성화 권장 (특히 관리자)
- ✅ Brute Force 공격 방어
- ✅ Account Lockout 정책

### 인가
- ✅ 최소 권한 원칙 적용
- ✅ RBAC로 역할 기반 관리
- ✅ 리소스 소유권 검증
- ✅ 권한 없음 시 403 반환
- ✅ 로그인 필요 시 401 반환

### 보안
- ✅ 토큰을 localStorage 대신 httpOnly 쿠키에 저장
- ✅ CSRF 토큰 사용 (쿠키 사용 시)
- ✅ Rate Limiting으로 API 남용 방지
- ✅ 보안 이벤트 로깅
- ✅ 정기적인 보안 감사

---

## 결론

인증과 인가는 보안의 최전선입니다. JWT, OAuth, Session, MFA 등 다양한 방법이 있지만, 각각의 장단점을 이해하고 프로젝트에 맞는 방식을 선택해야 합니다.

**권장 조합:**
- **SPA/모바일 앱**: JWT + Refresh Token + MFA
- **전통적인 웹앱**: Session + MFA
- **마이크로서비스**: JWT + OAuth 2.0
- **엔터프라이즈**: SAML 2.0 + MFA

보안은 지속적인 프로세스입니다. 최신 보안 트렌드를 주시하고, 정기적으로 보안 감사를 수행하세요.
