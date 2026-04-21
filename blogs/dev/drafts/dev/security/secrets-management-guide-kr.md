---
title: Secrets & Key Management - 비밀 정보 안전하게 관리하기
published: false
description: API 키, 비밀번호, 암호화 키 등 민감한 정보를 안전하게 관리하는 방법. 환경 변수, AWS Secrets Manager, HashiCorp Vault 등 실전 가이드.
tags: security, secrets, credentials, vault, aws
cover_image: https://example.com/your-cover-image.jpg
---

# Secrets & Key Management - 비밀 정보 안전하게 관리하기

API 키, 데이터베이스 비밀번호, 암호화 키 등 민감한 정보(Secrets)의 노출은 심각한 보안 사고로 이어집니다. 이 가이드에서는 Secrets를 안전하게 저장하고 관리하는 방법을 다룹니다.

---

## 1. 절대 하지 말아야 할 것 ❌

### 코드에 하드코딩

```javascript
// ❌ 절대 하지 마세요!
const API_KEY = 'sk-1234567890abcdefghijklmnop';
const DB_PASSWORD = 'MyS3cr3tP@ssw0rd!';
const JWT_SECRET = 'super-secret-key-123';
const STRIPE_SECRET = 'sk_live_51H...';

// 데이터베이스 연결
mongoose.connect('mongodb://admin:password123@localhost:27017/mydb');

// API 호출
fetch('https://api.example.com/data', {
  headers: { 'Authorization': 'Bearer sk-1234567890abcdef' }
});
```

**위험성:**
- GitHub에 푸시하면 전 세계에 공개
- Git 히스토리에 영구 저장
- 자동화된 봇이 수초 내에 탐지
- 즉각적인 보안 사고 발생 가능

### Git에 커밋

```javascript
// ❌ config.js 파일을 Git에 커밋
module.exports = {
  database: {
    host: 'prod-db.example.com',
    user: 'admin',
    password: 'Pr0dP@ssw0rd!',  // 노출!
    port: 5432
  },
  apiKeys: {
    stripe: 'sk_live_...',      // 노출!
    sendgrid: 'SG.abc123...',   // 노출!
    aws: {
      accessKeyId: 'AKIA...',   // 노출!
      secretAccessKey: '...'    // 노출!
    }
  }
};
```

### 클라이언트 사이드에 노출

```javascript
// ❌ 프론트엔드 코드에 API 키 포함
const API_KEY = 'AIzaSyC-xxxxxxxxxxxxxxxxxxx'; // 브라우저에서 보임!

// ❌ HTML에 직접 삽입
<script>
  const config = {
    apiKey: 'sk-1234567890abcdef'  // 소스 보기에서 보임!
  };
</script>
```

---

## 2. 환경 변수 (Environment Variables) ⭐️⭐️⭐️

### 기본 사용법

**.env 파일 생성**

```env
# .env 파일
NODE_ENV=production
PORT=3000

# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=myapp_user
DB_PASSWORD=secure_random_password_here
DB_NAME=myapp_production

# JWT
JWT_SECRET=your-256-bit-secret-key-here-use-crypto-random
JWT_EXPIRES_IN=1h
REFRESH_TOKEN_SECRET=another-256-bit-secret-for-refresh-tokens

# API Keys
STRIPE_SECRET_KEY=sk_live_51H...
SENDGRID_API_KEY=SG.abc123...
GOOGLE_CLIENT_ID=123456789-abc.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-...

# AWS
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=wJalrXUt...
AWS_REGION=us-east-1

# Redis
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=redis_secure_password
```

**.gitignore에 추가**

```gitignore
# .gitignore
.env
.env.local
.env.*.local
.env.production
config/secrets.json
*.key
*.pem
```

**dotenv 사용**

```javascript
// app.js
require('dotenv').config();

// 환경 변수 사용
const dbConfig = {
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
};

const jwtSecret = process.env.JWT_SECRET;
const stripeKey = process.env.STRIPE_SECRET_KEY;

// 필수 환경 변수 검증
const requiredEnvVars = [
  'DB_PASSWORD',
  'JWT_SECRET',
  'STRIPE_SECRET_KEY'
];

for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`❌ 필수 환경 변수 ${envVar}가 설정되지 않았습니다!`);
    process.exit(1);
  }
}
```

### .env.example 제공

```env
# .env.example (Git에 커밋 가능)
NODE_ENV=development
PORT=3000

# Database (로컬 개발용 예시)
DB_HOST=localhost
DB_PORT=5432
DB_USER=myapp_dev
DB_PASSWORD=change_this_password
DB_NAME=myapp_development

# JWT
JWT_SECRET=generate_a_random_256_bit_key
JWT_EXPIRES_IN=1h

# API Keys (실제 키는 별도 전달)
STRIPE_SECRET_KEY=sk_test_...
SENDGRID_API_KEY=your_sendgrid_key_here
```

---

## 3. AWS Secrets Manager ⭐️⭐️⭐️

### 개념

AWS Secrets Manager는 데이터베이스 자격 증명, API 키, 비밀번호 등을 안전하게 저장하고 회전(rotate)할 수 있는 관리형 서비스입니다.

### Secret 생성 (AWS CLI)

```bash
# Secret 생성
aws secretsmanager create-secret \
  --name myapp/production/database \
  --description "Production database credentials" \
  --secret-string '{
    "username": "admin",
    "password": "MyS3cur3P@ssw0rd!",
    "host": "prod-db.abc123.us-east-1.rds.amazonaws.com",
    "port": 5432,
    "database": "myapp_prod"
  }'

# Secret 조회
aws secretsmanager get-secret-value \
  --secret-id myapp/production/database

# Secret 업데이트
aws secretsmanager update-secret \
  --secret-id myapp/production/database \
  --secret-string '{"username":"admin","password":"NewPassword123"}'

# Secret 삭제 (30일 유예 기간)
aws secretsmanager delete-secret \
  --secret-id myapp/production/database \
  --recovery-window-in-days 30
```

### Node.js에서 사용

```javascript
const AWS = require('aws-sdk');

// AWS SDK 설정
const secretsManager = new AWS.SecretsManager({
  region: process.env.AWS_REGION || 'us-east-1'
});

// Secret 가져오기
async function getSecret(secretName) {
  try {
    const data = await secretsManager.getSecretValue({ 
      SecretId: secretName 
    }).promise();
    
    if ('SecretString' in data) {
      return JSON.parse(data.SecretString);
    } else {
      // Binary secret
      const buff = Buffer.from(data.SecretBinary, 'base64');
      return buff.toString('ascii');
    }
  } catch (err) {
    console.error(`Secret ${secretName}을 가져오는데 실패했습니다:`, err);
    throw err;
  }
}

// 캐싱으로 성능 향상
const secretCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5분

async function getCachedSecret(secretName) {
  const cached = secretCache.get(secretName);
  
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.value;
  }
  
  const value = await getSecret(secretName);
  secretCache.set(secretName, {
    value,
    timestamp: Date.now()
  });
  
  return value;
}

// 사용 예
async function initApp() {
  // 데이터베이스 설정
  const dbSecrets = await getCachedSecret('myapp/production/database');
  
  const dbConnection = await mongoose.connect(
    `mongodb://${dbSecrets.username}:${dbSecrets.password}@${dbSecrets.host}:${dbSecrets.port}/${dbSecrets.database}`
  );
  
  // API 키
  const apiSecrets = await getCachedSecret('myapp/production/api-keys');
  const stripeKey = apiSecrets.stripe;
  const sendgridKey = apiSecrets.sendgrid;
  
  console.log('✅ Secrets 로드 완료');
  
  // 서버 시작
  app.listen(3000);
}

initApp().catch(err => {
  console.error('앱 초기화 실패:', err);
  process.exit(1);
});
```

### Automatic Rotation (자동 회전)

```javascript
// Lambda 함수로 비밀번호 자동 회전
exports.handler = async (event) => {
  const { SecretId, Token, Step } = event;
  
  switch (Step) {
    case 'createSecret':
      // 새 비밀번호 생성
      const newPassword = generateSecurePassword();
      await secretsManager.putSecretValue({
        SecretId,
        ClientRequestToken: Token,
        SecretString: JSON.stringify({ password: newPassword }),
        VersionStages: ['AWSPENDING']
      }).promise();
      break;
      
    case 'setSecret':
      // 데이터베이스에 새 비밀번호 설정
      const pending = await getSecretVersion(SecretId, 'AWSPENDING');
      await updateDatabasePassword(pending.password);
      break;
      
    case 'testSecret':
      // 새 비밀번호로 연결 테스트
      const test = await getSecretVersion(SecretId, 'AWSPENDING');
      await testDatabaseConnection(test);
      break;
      
    case 'finishSecret':
      // 새 비밀번호를 현재 버전으로 설정
      await secretsManager.updateSecretVersionStage({
        SecretId,
        VersionStage: 'AWSCURRENT',
        MoveToVersionId: Token,
        RemoveFromVersionId: event.CurrentVersion
      }).promise();
      break;
  }
};
```

---

## 4. HashiCorp Vault ⭐️⭐️⭐️

### 개념

HashiCorp Vault는 엔터프라이즈급 비밀 관리 도구로, 동적 비밀 생성, 암호화 서비스, 감사 로깅 등을 제공합니다.

### Vault 설치 및 시작

```bash
# Vault 설치 (macOS)
brew install vault

# 개발 모드로 시작
vault server -dev

# 환경 변수 설정
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='<Root Token>'

# Secret 저장
vault kv put secret/myapp/database \
  username=admin \
  password=MyS3cur3P@ssw0rd \
  host=localhost \
  port=5432

# Secret 조회
vault kv get secret/myapp/database

# Secret 삭제
vault kv delete secret/myapp/database
```

### Node.js에서 사용

```javascript
const vault = require('node-vault')({
  endpoint: process.env.VAULT_ADDR || 'http://127.0.0.1:8200',
  token: process.env.VAULT_TOKEN
});

// Secret 읽기
async function getVaultSecret(path) {
  try {
    const result = await vault.read(path);
    return result.data.data; // KV v2 엔진
  } catch (err) {
    console.error(`Vault에서 ${path}를 읽는데 실패:`, err);
    throw err;
  }
}

// Secret 쓰기
async function setVaultSecret(path, data) {
  try {
    await vault.write(path, { data });
    console.log(`✅ Secret 저장 완료: ${path}`);
  } catch (err) {
    console.error(`Vault에 ${path}를 저장하는데 실패:`, err);
    throw err;
  }
}

// 동적 데이터베이스 자격 증명
async function getDynamicDbCredentials() {
  try {
    // Vault가 임시 DB 자격 증명 생성
    const creds = await vault.read('database/creds/my-role');
    
    return {
      username: creds.data.username,
      password: creds.data.password,
      leaseId: creds.lease_id,
      leaseDuration: creds.lease_duration // 초 단위
    };
  } catch (err) {
    console.error('동적 자격 증명 생성 실패:', err);
    throw err;
  }
}

// Lease 갱신
async function renewLease(leaseId) {
  await vault.write(`sys/leases/renew`, {
    lease_id: leaseId,
    increment: 3600 // 1시간 연장
  });
}

// 사용 예
async function initApp() {
  // 데이터베이스 설정
  const dbConfig = await getVaultSecret('secret/data/myapp/database');
  
  // 또는 동적 자격 증명 사용
  const dynamicCreds = await getDynamicDbCredentials();
  
  const db = await connectDatabase({
    host: dbConfig.host,
    username: dynamicCreds.username,
    password: dynamicCreds.password
  });
  
  // Lease 자동 갱신
  setInterval(() => {
    renewLease(dynamicCreds.leaseId);
  }, (dynamicCreds.leaseDuration - 300) * 1000); // 5분 전에 갱신
  
  app.listen(3000);
}
```

### Vault Policy (권한 관리)

```hcl
# myapp-policy.hcl
path "secret/data/myapp/*" {
  capabilities = ["read", "list"]
}

path "database/creds/my-role" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
```

```bash
# Policy 적용
vault policy write myapp-policy myapp-policy.hcl

# Token 생성
vault token create -policy=myapp-policy -ttl=24h
```

---

## 5. Azure Key Vault ⭐️⭐️⭐️

### Node.js에서 사용

```javascript
const { SecretClient } = require('@azure/keyvault-secrets');
const { DefaultAzureCredential } = require('@azure/identity');

const credential = new DefaultAzureCredential();
const vaultName = process.env.KEY_VAULT_NAME;
const vaultUrl = `https://${vaultName}.vault.azure.net`;

const client = new SecretClient(vaultUrl, credential);

// Secret 생성
async function setSecret(name, value) {
  await client.setSecret(name, value);
  console.log(`✅ Secret "${name}" 저장 완료`);
}

// Secret 조회
async function getSecret(name) {
  try {
    const secret = await client.getSecret(name);
    return secret.value;
  } catch (err) {
    console.error(`Secret "${name}"를 가져올 수 없습니다:`, err);
    throw err;
  }
}

// Secret 목록
async function listSecrets() {
  const secrets = [];
  for await (const secretProperties of client.listPropertiesOfSecrets()) {
    secrets.push(secretProperties.name);
  }
  return secrets;
}

// Secret 삭제
async function deleteSecret(name) {
  const poller = await client.beginDeleteSecret(name);
  await poller.pollUntilDone();
  console.log(`✅ Secret "${name}" 삭제 완료`);
}

// 사용 예
async function initApp() {
  const dbPassword = await getSecret('database-password');
  const apiKey = await getSecret('stripe-api-key');
  
  // 데이터베이스 연결
  await connectDatabase({
    password: dbPassword
  });
  
  app.listen(3000);
}
```

---

## 6. 환경별 Secret 관리

### 개발/스테이징/프로덕션 분리

```javascript
// config/index.js
const env = process.env.NODE_ENV || 'development';

const configs = {
  development: {
    db: {
      host: 'localhost',
      port: 5432,
      database: 'myapp_dev',
      user: process.env.DB_USER || 'dev_user',
      password: process.env.DB_PASSWORD || 'dev_password'
    },
    redis: {
      host: 'localhost',
      port: 6379
    },
    jwt: {
      secret: process.env.JWT_SECRET || 'dev-secret-key',
      expiresIn: '24h'
    }
  },
  
  staging: {
    db: {
      host: process.env.DB_HOST,
      port: process.env.DB_PORT,
      database: process.env.DB_NAME,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD
    },
    redis: {
      host: process.env.REDIS_HOST,
      port: process.env.REDIS_PORT,
      password: process.env.REDIS_PASSWORD
    },
    jwt: {
      secret: process.env.JWT_SECRET,
      expiresIn: '1h'
    }
  },
  
  production: {
    db: {
      host: process.env.DB_HOST,
      port: parseInt(process.env.DB_PORT),
      database: process.env.DB_NAME,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      ssl: true
    },
    redis: {
      host: process.env.REDIS_HOST,
      port: parseInt(process.env.REDIS_PORT),
      password: process.env.REDIS_PASSWORD,
      tls: {}
    },
    jwt: {
      secret: process.env.JWT_SECRET,
      expiresIn: '15m'
    }
  }
};

module.exports = configs[env];
```

---

## 7. CI/CD에서의 Secret 관리

### GitHub Actions

```yaml
# .github/workflows/deploy.yml
name: Deploy to Production

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      
      - name: Deploy to ECS
        env:
          DB_PASSWORD: ${{ secrets.DB_PASSWORD }}
          JWT_SECRET: ${{ secrets.JWT_SECRET }}
          STRIPE_KEY: ${{ secrets.STRIPE_SECRET_KEY }}
        run: |
          # 배포 스크립트 실행
          ./deploy.sh
```

### GitLab CI

```yaml
# .gitlab-ci.yml
deploy:
  stage: deploy
  only:
    - main
  variables:
    NODE_ENV: "production"
  script:
    - export DB_PASSWORD=$DB_PASSWORD
    - export JWT_SECRET=$JWT_SECRET
    - ./deploy.sh
  environment:
    name: production
```

---

## 8. Secret 회전 (Rotation)

### 자동 회전 전략

```javascript
// Secret 회전 스케줄러
const cron = require('node-cron');

// 매달 1일 새벽 2시에 API 키 회전
cron.schedule('0 2 1 * *', async () => {
  console.log('🔄 API 키 회전 시작...');
  
  try {
    // 1. 새 API 키 생성
    const newApiKey = await generateNewApiKey();
    
    // 2. Secrets Manager에 저장
    await secretsManager.updateSecret({
      SecretId: 'myapp/api-keys',
      SecretString: JSON.stringify({
        current: newApiKey,
        previous: oldApiKey  // 한 주기 동안 이전 키도 유지
      })
    }).promise();
    
    // 3. 파트너사에 새 키 전달 (자동 또는 수동)
    await notifyPartners(newApiKey);
    
    // 4. 30일 후 이전 키 완전 삭제
    scheduleKeyDeletion(oldApiKey, 30);
    
    console.log('✅ API 키 회전 완료');
  } catch (err) {
    console.error('❌ API 키 회전 실패:', err);
    // 알림 전송
    await sendAlert('API 키 회전 실패', err);
  }
});
```

---

## 베스트 프랙티스 요약

### 저장
- ✅ 절대 코드에 하드코딩하지 않기
- ✅ .env 파일은 .gitignore에 추가
- ✅ 프로덕션에서는 Secrets Manager 사용
- ✅ 환경별로 다른 Secret 사용
- ✅ Secret은 암호화하여 저장

### 접근
- ✅ 최소 권한 원칙 적용
- ✅ Secret 접근 로그 기록
- ✅ 임시 자격 증명 사용 (가능한 경우)
- ✅ Secret 캐싱으로 성능 향상
- ✅ 만료 시간 설정

### 관리
- ✅ Secret 정기적으로 회전
- ✅ 사용하지 않는 Secret 삭제
- ✅ Secret 변경 이력 추적
- ✅ .env.example 제공
- ✅ 팀원 교육 및 문서화

### 모니터링
- ✅ Secret 접근 이상 탐지
- ✅ Secret 만료 알림
- ✅ GitHub에 Secret 푸시 감지
- ✅ Secret 회전 실패 알림

---

## 결론

Secret 관리는 보안의 기본입니다. 개발 단계에서는 환경 변수로 시작하되, 프로덕션에서는 반드시 AWS Secrets Manager, HashiCorp Vault, Azure Key Vault 같은 전문 도구를 사용하세요.

**권장 전략:**
- **로컬 개발**: .env 파일
- **스테이징/프로덕션**: Secrets Manager
- **엔터프라이즈**: HashiCorp Vault
- **다중 클라우드**: Vault 또는 각 클라우드의 Secret 서비스

Secret이 한 번 노출되면 되돌릴 수 없습니다. 예방이 최선입니다!
