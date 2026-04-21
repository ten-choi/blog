---
title: Logging & Monitoring - 보안 이벤트 추적 가이드
published: false
description: 보안 이벤트 로깅, 실시간 모니터링, 인시던트 대응. Winston, ELK Stack, Prometheus, Sentry 활용법을 상세히 설명합니다.
tags: security, logging, monitoring, observability, incident-response
cover_image: https://example.com/your-cover-image.jpg
---

# Logging & Monitoring - 보안 이벤트 추적 가이드

로깅과 모니터링은 보안 사고를 조기에 탐지하고 신속하게 대응하는 핵심 수단입니다. 이 가이드에서는 효과적인 보안 로깅과 실시간 모니터링 구축 방법을 다룹니다.

---

## 1. 무엇을 로깅해야 하는가?

### ✅ 로깅해야 할 보안 이벤트

```javascript
// 1. 인증 이벤트
- 로그인 시도 (성공/실패)
- 로그아웃
- 비밀번호 변경/재설정
- MFA 활성화/비활성화
- 토큰 발급/갱신

// 2. 인가 이벤트
- 권한 없는 접근 시도
- 역할 변경
- 권한 승격 시도

// 3. 데이터 접근
- 민감한 데이터 조회
- 데이터 생성/수정/삭제
- 대량 데이터 다운로드

// 4. 시스템 이벤트
- 설정 변경
- 관리자 작업
- API 키 생성/삭제
- 서비스 시작/중지

// 5. 보안 이벤트
- SQL Injection 시도
- XSS 공격 시도
- Rate Limiting 초과
- 비정상적인 요청 패턴
```

### ❌ 절대 로깅하면 안 되는 것

```javascript
// 개인정보 및 민감 정보
- 비밀번호 (평문 또는 해시)
- 신용카드 번호
- 주민등록번호
- API Keys, Secrets
- JWT 토큰 (전체)
- 세션 ID
- 개인 식별 정보 (GDPR 위반)
```

---

## 2. Winston으로 구조화된 로깅 ⭐️⭐️⭐️

### 설치 및 기본 설정

```bash
npm install winston winston-daily-rotate-file
```

```javascript
// logger.js
const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');

// 로그 포맷 정의
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

// Transport 설정
const transports = [
  // 에러 로그 (별도 파일)
  new DailyRotateFile({
    filename: 'logs/error-%DATE%.log',
    datePattern: 'YYYY-MM-DD',
    level: 'error',
    maxSize: '20m',
    maxFiles: '14d',
    zippedArchive: true
  }),
  
  // 모든 로그
  new DailyRotateFile({
    filename: 'logs/combined-%DATE%.log',
    datePattern: 'YYYY-MM-DD',
    maxSize: '20m',
    maxFiles: '30d',
    zippedArchive: true
  }),
  
  // 보안 이벤트 전용
  new DailyRotateFile({
    filename: 'logs/security-%DATE%.log',
    datePattern: 'YYYY-MM-DD',
    level: 'warn',
    maxSize: '20m',
    maxFiles: '90d'
  })
];

// 개발 환경에서는 콘솔 출력
if (process.env.NODE_ENV !== 'production') {
  transports.push(
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    })
  );
}

// Logger 생성
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  defaultMeta: { 
    service: 'api-service',
    environment: process.env.NODE_ENV
  },
  transports
});

module.exports = logger;
```

### 보안 이벤트 로깅

```javascript
const logger = require('./logger');

// HTTP 요청 로깅 미들웨어
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

// 인증 실패 로깅
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  const user = await authenticateUser(email, password);
  
  if (!user) {
    logger.warn('Login failed', {
      event: 'AUTH_FAILURE',
      email,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      timestamp: new Date().toISOString()
    });
    
    return res.status(401).json({ error: '인증 실패' });
  }
  
  logger.info('Login successful', {
    event: 'AUTH_SUCCESS',
    userId: user.id,
    email: user.email,
    ip: req.ip
  });
  
  // 토큰 발급...
});

// 권한 오류 로깅
app.delete('/api/users/:id', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    logger.warn('Unauthorized access attempt', {
      event: 'AUTHZ_FAILURE',
      userId: req.user.id,
      action: 'DELETE_USER',
      targetUserId: req.params.id,
      ip: req.ip,
      path: req.path
    });
    
    return res.status(403).json({ error: '권한이 없습니다' });
  }
  
  logger.info('User deleted', {
    event: 'USER_DELETED',
    deletedBy: req.user.id,
    deletedUser: req.params.id
  });
  
  // 삭제 로직...
});

// SQL Injection 시도 탐지
app.use((req, res, next) => {
  const suspicious = /(\bor\b|\band\b|--|;|\/\*|\*\/|xp_|sp_|exec|execute|select|insert|update|delete|drop|create|alter)/i;
  
  const params = JSON.stringify(req.query) + JSON.stringify(req.body);
  
  if (suspicious.test(params)) {
    logger.error('SQL Injection attempt detected', {
      event: 'SQL_INJECTION_ATTEMPT',
      ip: req.ip,
      url: req.url,
      method: req.method,
      params: req.query,
      body: req.body,
      userAgent: req.get('user-agent')
    });
    
    return res.status(400).json({ error: '잘못된 요청입니다' });
  }
  
  next();
});

// Rate Limiting 초과
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  handler: (req, res) => {
    logger.warn('Rate limit exceeded', {
      event: 'RATE_LIMIT_EXCEEDED',
      ip: req.ip,
      url: req.url,
      userAgent: req.get('user-agent'),
      userId: req.user?.id
    });
    
    res.status(429).json({ error: '너무 많은 요청' });
  }
});

// 에러 로깅
app.use((err, req, res, next) => {
  logger.error('Application error', {
    event: 'ERROR',
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

---

## 3. ELK Stack (Elasticsearch + Logstash + Kibana) ⭐️⭐️⭐️

### 개념

- **Elasticsearch**: 로그 저장 및 검색
- **Logstash**: 로그 수집 및 변환
- **Kibana**: 로그 시각화 및 분석

### Winston에서 Elasticsearch로 전송

```javascript
const winston = require('winston');
const { ElasticsearchTransport } = require('winston-elasticsearch');

const esTransportOpts = {
  level: 'info',
  clientOpts: { 
    node: process.env.ELASTICSEARCH_URL || 'http://localhost:9200',
    auth: {
      username: process.env.ES_USERNAME,
      password: process.env.ES_PASSWORD
    }
  },
  index: 'logs',
  indexPrefix: 'app-logs',
  dataStream: true
};

const logger = winston.createLogger({
  transports: [
    new ElasticsearchTransport(esTransportOpts),
    new winston.transports.Console()
  ]
});

module.exports = logger;
```

### Logstash 설정

```ruby
# logstash.conf
input {
  file {
    path => "/var/log/app/combined-*.log"
    type => "app-log"
    codec => "json"
  }
}

filter {
  # IP 기반 지리 정보 추가
  geoip {
    source => "ip"
  }
  
  # User Agent 파싱
  useragent {
    source => "userAgent"
  }
  
  # 타임스탬프 파싱
  date {
    match => [ "timestamp", "ISO8601" ]
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "app-logs-%{+YYYY.MM.dd}"
  }
}
```

### Kibana 대시보드 쿼리

```json
// 로그인 실패 검색
{
  "query": {
    "bool": {
      "must": [
        { "match": { "event": "AUTH_FAILURE" } },
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ]
    }
  }
}

// 특정 IP의 모든 활동
{
  "query": {
    "match": { "ip": "192.168.1.100" }
  }
}

// 권한 오류 통계
{
  "aggs": {
    "by_user": {
      "terms": { "field": "userId" },
      "aggs": {
        "failed_attempts": {
          "filter": { "term": { "event": "AUTHZ_FAILURE" } }
        }
      }
    }
  }
}
```

---

## 4. Prometheus + Grafana ⭐️⭐️⭐️

### Prometheus로 메트릭 수집

```javascript
const promClient = require('prom-client');

// Metrics Registry
const register = new promClient.Registry();

// 기본 메트릭 수집 (CPU, 메모리 등)
promClient.collectDefaultMetrics({ 
  register,
  prefix: 'app_'
});

// 커스텀 메트릭 정의
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
  buckets: [0.1, 0.5, 1, 2, 5],
  registers: [register]
});

const loginAttempts = new promClient.Counter({
  name: 'login_attempts_total',
  help: 'Total number of login attempts',
  labelNames: ['status'],
  registers: [register]
});

const authErrors = new promClient.Counter({
  name: 'auth_errors_total',
  help: 'Total number of authentication errors',
  labelNames: ['type'],
  registers: [register]
});

// 미들웨어로 메트릭 수집
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

// 로그인 메트릭
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  const user = await authenticateUser(email, password);
  
  if (!user) {
    loginAttempts.inc({ status: 'failed' });
    authErrors.inc({ type: 'invalid_credentials' });
    return res.status(401).json({ error: '인증 실패' });
  }
  
  loginAttempts.inc({ status: 'success' });
  
  // 토큰 발급...
});

// Metrics 엔드포인트
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
});
```

### Prometheus 설정

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'node-app'
    static_configs:
      - targets: ['localhost:3000']
```

### Grafana 대시보드 쿼리

```promql
# HTTP 요청 속도 (RPS)
rate(http_requests_total[5m])

# 에러율
rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m]) * 100

# 평균 응답 시간
rate(http_request_duration_seconds_sum[5m]) / rate(http_request_duration_seconds_count[5m])

# 로그인 실패율
rate(login_attempts_total{status="failed"}[5m])

# 인증 에러 타입별 집계
sum by (type) (rate(auth_errors_total[5m]))
```

---

## 5. Sentry로 에러 추적 ⭐️⭐️

### 설치 및 설정

```bash
npm install @sentry/node @sentry/tracing
```

```javascript
const Sentry = require('@sentry/node');
const Tracing = require('@sentry/tracing');

Sentry.init({
  dsn: process.env.SENTRY_DSN,
  environment: process.env.NODE_ENV,
  tracesSampleRate: 1.0,
  
  // 성능 모니터링
  integrations: [
    new Tracing.Integrations.Express({ app })
  ]
});

// Request handler (가장 먼저)
app.use(Sentry.Handlers.requestHandler());

// Tracing handler
app.use(Sentry.Handlers.tracingHandler());

// 라우트들...

// Error handler (가장 마지막)
app.use(Sentry.Handlers.errorHandler());

// 커스텀 에러 핸들러
app.use((err, req, res, next) => {
  // 보안 관련 에러는 높은 우선순위로 처리
  if (err.type === 'SECURITY') {
    Sentry.captureException(err, {
      level: 'error',
      tags: {
        type: 'security',
        ip: req.ip
      },
      user: {
        id: req.user?.id,
        email: req.user?.email
      },
      extra: {
        url: req.url,
        method: req.method
      }
    });
  }
  
  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production' 
      ? '서버 오류가 발생했습니다' 
      : err.message
  });
});
```

### 보안 이벤트 추적

```javascript
// SQL Injection 시도
if (suspiciousPattern.test(input)) {
  Sentry.captureMessage('SQL Injection attempt detected', {
    level: 'warning',
    tags: { type: 'sql_injection' },
    extra: { input, ip: req.ip }
  });
}

// 권한 없는 접근
if (!hasPermission) {
  Sentry.captureMessage('Unauthorized access attempt', {
    level: 'warning',
    tags: { type: 'unauthorized_access' },
    user: { id: req.user.id },
    extra: { resource: req.params.id }
  });
}

// 비정상적인 활동
if (isAnomalous) {
  Sentry.captureMessage('Anomalous activity detected', {
    level: 'error',
    tags: { type: 'anomaly' },
    extra: { activity, frequency }
  });
}
```

---

## 6. 실시간 알림 ⭐️⭐️⭐️

### Slack 알림

```javascript
const axios = require('axios');

class AlertService {
  constructor(webhookUrl) {
    this.webhookUrl = webhookUrl;
  }
  
  async sendAlert(title, message, level = 'warning') {
    const color = {
      info: '#36a64f',
      warning: '#ff9900',
      error: '#ff0000',
      critical: '#8B0000'
    }[level];
    
    const payload = {
      attachments: [{
        color,
        title,
        text: message,
        fields: [
          {
            title: 'Environment',
            value: process.env.NODE_ENV,
            short: true
          },
          {
            title: 'Timestamp',
            value: new Date().toISOString(),
            short: true
          }
        ],
        footer: 'Security Alert',
        ts: Math.floor(Date.now() / 1000)
      }]
    };
    
    try {
      await axios.post(this.webhookUrl, payload);
    } catch (err) {
      console.error('Slack 알림 전송 실패:', err);
    }
  }
}

const alertService = new AlertService(process.env.SLACK_WEBHOOK_URL);

// 사용 예
const loginAttempts = new Map();

app.post('/api/login', async (req, res) => {
  const { email } = req.body;
  const attempts = loginAttempts.get(email) || 0;
  
  // 5회 이상 실패 시 알림
  if (attempts >= 5) {
    await alertService.sendAlert(
      '🚨 보안 경고: 반복된 로그인 실패',
      `계정 ${email}에 대해 ${attempts}회 로그인 실패\nIP: ${req.ip}\nUser-Agent: ${req.get('user-agent')}`,
      'warning'
    );
  }
  
  // 인증 로직...
});

// SQL Injection 시도 시 즉시 알림
if (isSQLInjection) {
  await alertService.sendAlert(
    '🔴 긴급: SQL Injection 시도 탐지',
    `IP: ${req.ip}\nURL: ${req.url}\nPayload: ${suspiciousInput}`,
    'critical'
  );
}
```

### 이메일 알림

```javascript
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransporter({
  host: process.env.SMTP_HOST,
  port: 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

async function sendSecurityAlert(subject, details) {
  const mailOptions = {
    from: 'security@example.com',
    to: 'admin@example.com',
    subject: `[보안 알림] ${subject}`,
    html: `
      <h2>${subject}</h2>
      <p><strong>발생 시간:</strong> ${new Date().toISOString()}</p>
      <p><strong>상세 내용:</strong></p>
      <pre>${JSON.stringify(details, null, 2)}</pre>
    `
  };
  
  try {
    await transporter.sendMail(mailOptions);
  } catch (err) {
    console.error('이메일 전송 실패:', err);
  }
}
```

---

## 7. 로그 보안 및 컴플라이언스

### 민감 정보 마스킹

```javascript
function maskSensitiveData(data) {
  const masked = { ...data };
  
  // 비밀번호 마스킹
  if (masked.password) {
    masked.password = '***REDACTED***';
  }
  
  // 이메일 부분 마스킹
  if (masked.email) {
    const [local, domain] = masked.email.split('@');
    masked.email = `${local[0]}***@${domain}`;
  }
  
  // 신용카드 마스킹
  if (masked.cardNumber) {
    masked.cardNumber = `****-****-****-${masked.cardNumber.slice(-4)}`;
  }
  
  // JWT 토큰 마스킹
  if (masked.token) {
    masked.token = `${masked.token.slice(0, 10)}...`;
  }
  
  return masked;
}

// 로깅 전 마스킹
app.use((req, res, next) => {
  const originalBody = req.body;
  req.body = maskSensitiveData(originalBody);
  next();
});
```

### 로그 보존 기간

```javascript
// 로그 정리 스케줄러
const cron = require('node-cron');
const fs = require('fs').promises;
const path = require('path');

// 매일 새벽 3시에 오래된 로그 삭제
cron.schedule('0 3 * * *', async () => {
  const logsDir = './logs';
  const retentionDays = {
    error: 90,      // 에러 로그는 90일
    security: 365,  // 보안 로그는 1년
    combined: 30    // 일반 로그는 30일
  };
  
  try {
    const files = await fs.readdir(logsDir);
    const now = Date.now();
    
    for (const file of files) {
      const filePath = path.join(logsDir, file);
      const stats = await fs.stat(filePath);
      const ageInDays = (now - stats.mtimeMs) / (1000 * 60 * 60 * 24);
      
      let retention = retentionDays.combined;
      if (file.includes('error')) retention = retentionDays.error;
      if (file.includes('security')) retention = retentionDays.security;
      
      if (ageInDays > retention) {
        await fs.unlink(filePath);
        console.log(`Deleted old log: ${file}`);
      }
    }
  } catch (err) {
    console.error('로그 정리 실패:', err);
  }
});
```

---

## 베스트 프랙티스 요약

### 로깅
- ✅ 구조화된 JSON 로깅
- ✅ 모든 보안 이벤트 기록
- ✅ 민감 정보 마스킹
- ✅ 타임스탬프 포함
- ✅ 컨텍스트 정보 추가 (IP, User Agent 등)

### 모니터링
- ✅ 실시간 대시보드 구축
- ✅ 이상 징후 자동 탐지
- ✅ 임계값 기반 알림
- ✅ 여러 채널로 알림 (Slack, 이메일 등)
- ✅ On-call 로테이션

### 컴플라이언스
- ✅ GDPR 준수 (개인정보 마스킹)
- ✅ 로그 보존 기간 정책
- ✅ 접근 제어
- ✅ 암호화 저장
- ✅ 감사 추적

---

## 결론

로깅과 모니터링은 보안의 눈과 귀입니다. 단순히 로그를 남기는 것이 아니라, 의미 있는 정보를 기록하고 실시간으로 분석하여 위협에 신속히 대응해야 합니다.

**권장 스택:**
- **로깅**: Winston + ELK Stack
- **메트릭**: Prometheus + Grafana
- **에러 추적**: Sentry
- **알림**: Slack + PagerDuty

보안은 사후 대응이 아닌 사전 예방입니다!
