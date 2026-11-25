---
title: "Logging & Monitoring - A Guide to Tracking Security Events"
labels: ["security","logging","monitoring","observability","incident-response","Archive"]
published: true
date: 2025-02-08T10:41:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "8620101333877395326"
source: "archive"
archivePath: "_archive/dev/security/logging-monitoring-guide-kr.md"
---

# Logging & Monitoring - A Guide to Tracking Security Events

Logging and monitoring are your core tools for detecting security incidents early and responding quickly. This guide covers how to build effective security logging and real-time monitoring.

---

## 1. What Should You Log?

### ✅ Security Events You Should Log

```javascript
// 1. Authentication events
- Login attempts (success/failure)
- Logouts
- Password changes/resets
- MFA enabled/disabled
- Token issuance/refresh

// 2. Authorization events
- Unauthorized access attempts
- Role changes
- Privilege escalation attempts

// 3. Data access
- Reads of sensitive data
- Data creation/modification/deletion
- Bulk data downloads

// 4. System events
- Configuration changes
- Admin operations
- API key creation/deletion
- Service start/stop

// 5. Security events
- SQL injection attempts
- XSS attack attempts
- Rate limit exceeded
- Abnormal request patterns
```

### ❌ Things You Must Never Log

```javascript
// Personal and sensitive information
- Passwords (plaintext or hashed)
- Credit card numbers
- National ID numbers (e.g., resident registration numbers)
- API keys, secrets
- JWT tokens (in full)
- Session IDs
- Personally identifiable information (a GDPR violation)
```

---

## 2. Structured Logging with Winston ⭐️⭐️⭐️

### Installation and Basic Setup

```bash
npm install winston winston-daily-rotate-file
```

```javascript
// logger.js
const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');

// Define the log format
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

// Transport configuration
const transports = [
  // Error logs (separate file)
  new DailyRotateFile({
    filename: 'logs/error-%DATE%.log',
    datePattern: 'YYYY-MM-DD',
    level: 'error',
    maxSize: '20m',
    maxFiles: '14d',
    zippedArchive: true
  }),
  
  // All logs
  new DailyRotateFile({
    filename: 'logs/combined-%DATE%.log',
    datePattern: 'YYYY-MM-DD',
    maxSize: '20m',
    maxFiles: '30d',
    zippedArchive: true
  }),
  
  // Security events only
  new DailyRotateFile({
    filename: 'logs/security-%DATE%.log',
    datePattern: 'YYYY-MM-DD',
    level: 'warn',
    maxSize: '20m',
    maxFiles: '90d'
  })
];

// Print to the console in development
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

// Create the logger
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

### Logging Security Events

```javascript
const logger = require('./logger');

// HTTP request logging middleware
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

// Log authentication failures
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
    
    return res.status(401).json({ error: 'Authentication failed' });
  }
  
  logger.info('Login successful', {
    event: 'AUTH_SUCCESS',
    userId: user.id,
    email: user.email,
    ip: req.ip
  });
  
  // Issue a token...
});

// Log authorization errors
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
    
    return res.status(403).json({ error: 'Permission denied' });
  }
  
  logger.info('User deleted', {
    event: 'USER_DELETED',
    deletedBy: req.user.id,
    deletedUser: req.params.id
  });
  
  // Deletion logic...
});

// Detect SQL injection attempts
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
    
    return res.status(400).json({ error: 'Bad request' });
  }
  
  next();
});

// Rate limit exceeded
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
    
    res.status(429).json({ error: 'Too many requests' });
  }
});

// Error logging
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
  
  res.status(500).json({ error: 'An internal server error occurred' });
});
```

---

## 3. ELK Stack (Elasticsearch + Logstash + Kibana) ⭐️⭐️⭐️

### Concept

- **Elasticsearch**: stores and searches logs
- **Logstash**: collects and transforms logs
- **Kibana**: visualizes and analyzes logs

### Shipping from Winston to Elasticsearch

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

### Logstash Configuration

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
  # Add geolocation based on IP
  geoip {
    source => "ip"
  }
  
  # Parse the user agent
  useragent {
    source => "userAgent"
  }
  
  # Parse the timestamp
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

### Kibana Dashboard Queries

```json
// Search for failed logins
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

// All activity from a specific IP
{
  "query": {
    "match": { "ip": "192.168.1.100" }
  }
}

// Authorization error stats
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

### Collecting Metrics with Prometheus

```javascript
const promClient = require('prom-client');

// Metrics Registry
const register = new promClient.Registry();

// Collect default metrics (CPU, memory, etc.)
promClient.collectDefaultMetrics({ 
  register,
  prefix: 'app_'
});

// Define custom metrics
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

// Collect metrics in middleware
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

// Login metrics
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  const user = await authenticateUser(email, password);
  
  if (!user) {
    loginAttempts.inc({ status: 'failed' });
    authErrors.inc({ type: 'invalid_credentials' });
    return res.status(401).json({ error: 'Authentication failed' });
  }
  
  loginAttempts.inc({ status: 'success' });
  
  // Issue a token...
});

// Metrics endpoint
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
});
```

### Prometheus Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'node-app'
    static_configs:
      - targets: ['localhost:3000']
```

### Grafana Dashboard Queries

```promql
# HTTP request rate (RPS)
rate(http_requests_total[5m])

# Error rate
rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m]) * 100

# Average response time
rate(http_request_duration_seconds_sum[5m]) / rate(http_request_duration_seconds_count[5m])

# Login failure rate
rate(login_attempts_total{status="failed"}[5m])

# Auth errors by type
sum by (type) (rate(auth_errors_total[5m]))
```

---

## 5. Error Tracking with Sentry ⭐️⭐️

### Installation and Setup

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
  
  // Performance monitoring
  integrations: [
    new Tracing.Integrations.Express({ app })
  ]
});

// Request handler (must come first)
app.use(Sentry.Handlers.requestHandler());

// Tracing handler
app.use(Sentry.Handlers.tracingHandler());

// Routes...

// Error handler (must come last)
app.use(Sentry.Handlers.errorHandler());

// Custom error handler
app.use((err, req, res, next) => {
  // Treat security-related errors as high priority
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
      ? 'An internal server error occurred' 
      : err.message
  });
});
```

### Tracking Security Events

```javascript
// SQL injection attempt
if (suspiciousPattern.test(input)) {
  Sentry.captureMessage('SQL Injection attempt detected', {
    level: 'warning',
    tags: { type: 'sql_injection' },
    extra: { input, ip: req.ip }
  });
}

// Unauthorized access
if (!hasPermission) {
  Sentry.captureMessage('Unauthorized access attempt', {
    level: 'warning',
    tags: { type: 'unauthorized_access' },
    user: { id: req.user.id },
    extra: { resource: req.params.id }
  });
}

// Anomalous activity
if (isAnomalous) {
  Sentry.captureMessage('Anomalous activity detected', {
    level: 'error',
    tags: { type: 'anomaly' },
    extra: { activity, frequency }
  });
}
```

---

## 6. Real-Time Alerts ⭐️⭐️⭐️

### Slack Alerts

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
      console.error('Failed to send Slack alert:', err);
    }
  }
}

const alertService = new AlertService(process.env.SLACK_WEBHOOK_URL);

// Usage example
const loginAttempts = new Map();

app.post('/api/login', async (req, res) => {
  const { email } = req.body;
  const attempts = loginAttempts.get(email) || 0;
  
  // Alert after 5 or more failures
  if (attempts >= 5) {
    await alertService.sendAlert(
      '🚨 Security warning: repeated login failures',
      `${attempts} failed logins for account ${email}\nIP: ${req.ip}\nUser-Agent: ${req.get('user-agent')}`,
      'warning'
    );
  }
  
  // Authentication logic...
});

// Alert immediately on a SQL injection attempt
if (isSQLInjection) {
  await alertService.sendAlert(
    '🔴 Urgent: SQL injection attempt detected',
    `IP: ${req.ip}\nURL: ${req.url}\nPayload: ${suspiciousInput}`,
    'critical'
  );
}
```

### Email Alerts

```javascript
const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
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
    subject: `[Security Alert] ${subject}`,
    html: `
      <h2>${subject}</h2>
      <p><strong>Time:</strong> ${new Date().toISOString()}</p>
      <p><strong>Details:</strong></p>
      <pre>${JSON.stringify(details, null, 2)}</pre>
    `
  };
  
  try {
    await transporter.sendMail(mailOptions);
  } catch (err) {
    console.error('Failed to send email:', err);
  }
}
```

---

## 7. Log Security and Compliance

### Masking Sensitive Data

```javascript
function maskSensitiveData(data) {
  const masked = { ...data };
  
  // Mask passwords
  if (masked.password) {
    masked.password = '***REDACTED***';
  }
  
  // Partially mask email addresses
  if (masked.email) {
    const [local, domain] = masked.email.split('@');
    masked.email = `${local[0]}***@${domain}`;
  }
  
  // Mask credit card numbers
  if (masked.cardNumber) {
    masked.cardNumber = `****-****-****-${masked.cardNumber.slice(-4)}`;
  }
  
  // Mask JWT tokens
  if (masked.token) {
    masked.token = `${masked.token.slice(0, 10)}...`;
  }
  
  return masked;
}

// Mask before logging
app.use((req, res, next) => {
  const originalBody = req.body;
  req.body = maskSensitiveData(originalBody);
  next();
});
```

### Log Retention

```javascript
// Log cleanup scheduler
const cron = require('node-cron');
const fs = require('fs').promises;
const path = require('path');

// Delete old logs every day at 3 AM
cron.schedule('0 3 * * *', async () => {
  const logsDir = './logs';
  const retentionDays = {
    error: 90,      // Error logs: 90 days
    security: 365,  // Security logs: 1 year
    combined: 30    // General logs: 30 days
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
    console.error('Log cleanup failed:', err);
  }
});
```

---

## Best Practices Summary

### Logging
- ✅ Structured JSON logging
- ✅ Record every security event
- ✅ Mask sensitive data
- ✅ Include timestamps
- ✅ Add context (IP, user agent, etc.)

### Monitoring
- ✅ Build real-time dashboards
- ✅ Detect anomalies automatically
- ✅ Threshold-based alerts
- ✅ Alerts across multiple channels (Slack, email, etc.)
- ✅ On-call rotation

### Compliance
- ✅ GDPR compliance (mask personal data)
- ✅ Log retention policy
- ✅ Access control
- ✅ Encrypted storage
- ✅ Audit trails

---

## Conclusion

Logging and monitoring are the eyes and ears of security. It's not just about leaving logs behind - you need to record meaningful information, analyze it in real time, and respond to threats quickly.

**Recommended stack:**
- **Logging**: Winston + ELK Stack
- **Metrics**: Prometheus + Grafana
- **Error tracking**: Sentry
- **Alerting**: Slack + PagerDuty

Security is about prevention, not cleanup after the fact!
