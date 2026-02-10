---
title: Supply Chain Security - 의존성 보안 가이드
published: false
description: npm/pip 패키지 의존성 관리, 취약점 스캔, 공급망 공격 방어. Dependabot, Snyk, npm audit 활용법을 상세히 설명합니다.
tags: security, supply-chain, dependencies, vulnerability, open-source
cover_image: https://example.com/your-cover-image.jpg
---

# Supply Chain Security - 의존성 보안 가이드

소프트웨어 공급망 공격은 최근 가장 빠르게 증가하는 보안 위협입니다. 평균적으로 애플리케이션 코드의 80%가 오픈소스 라이브러리입니다. 이 가이드에서는 의존성을 안전하게 관리하는 방법을 다룹니다.

---

## 1. 공급망 공격이란? ⭐️⭐️⭐️

### 실제 사례

#### 1) event-stream 공격 (2018)
```javascript
// 악의적인 코드가 숨겨진 패키지
// event-stream@3.3.6에 암호화폐 지갑을 훔치는 코드 삽입
```

피해: 200만+ 다운로드, Copay 비트코인 지갑 침해

#### 2) colors.js / faker.js 사건 (2022)
```javascript
// 개발자가 의도적으로 악성 코드 삽입
// 무한 루프로 애플리케이션 마비
while(true) {
  console.log('LIBERTY LIBERTY LIBERTY');
}
```

#### 3) SolarWinds 공격 (2020)
빌드 시스템 침해로 18,000개 조직에 악성 코드 배포

### 공급망 공격 유형

```javascript
/*
1. 직접 의존성 침해 (Direct Dependency Compromise)
   - 악의적인 패키지 업로드
   - 타이포스쿼팅 (typosquatting)

2. 간접 의존성 공격 (Transitive Dependency Attack)
   - 의존성의 의존성 침해
   - 깊은 의존성 트리 악용

3. 계정 탈취 (Account Takeover)
   - 메인테이너 계정 해킹
   - 악의적인 업데이트 배포

4. 빌드 시스템 침해 (Build System Compromise)
   - CI/CD 파이프라인 공격
   - 배포 과정에 악성 코드 삽입
*/
```

---

## 2. npm/yarn 의존성 보안 ⭐️⭐️⭐️

### package.json 보안 설정

```json
{
  "name": "my-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.18.2",
    "jsonwebtoken": "9.0.0"
  },
  "devDependencies": {
    "eslint": "8.40.0"
  },
  "scripts": {
    "preinstall": "npx npm-force-resolutions",
    "audit": "npm audit --audit-level=high",
    "audit-fix": "npm audit fix --force"
  },
  "resolutions": {
    "**/**/minimist": "^1.2.6"
  },
  "engines": {
    "node": ">=18.0.0",
    "npm": ">=9.0.0"
  }
}
```

### npm audit 사용

```bash
# 취약점 검사
npm audit

# 자동 수정 (minor/patch 버전만)
npm audit fix

# 위험한 업데이트 포함 (주의!)
npm audit fix --force

# 특정 심각도 이상만 검사
npm audit --audit-level=high

# JSON 형식으로 출력
npm audit --json
```

### package-lock.json 중요성

```json
// package-lock.json은 정확한 버전 고정
{
  "name": "my-app",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "node_modules/express": {
      "version": "4.18.2",
      "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
      "integrity": "sha512-5/PsL6iGPdfQ/lKM1UuielYgv3BUoJfz1aUwU9vHZ+J7gyvwdQXFEBIEIaxeGf0GIcreATNyBExtalisDbuMqQ=="
    }
  }
}
```

**❌ 절대 하지 말 것:**
```bash
# package-lock.json 삭제 금지!
rm package-lock.json

# .gitignore에 추가 금지!
package-lock.json
```

### 타이포스쿼팅 방지

```javascript
// ❌ 위험: 오타로 악성 패키지 설치
npm install experss  // express의 오타
npm install reqeust  // request의 오타
npm install loadsh   // lodash의 오타

// ✅ 안전: 항상 공식 문서 확인
// https://www.npmjs.com/package/express
npm install express
```

---

## 3. 자동화된 취약점 스캔 ⭐️⭐️⭐️

### 1) Snyk

```bash
# Snyk CLI 설치
npm install -g snyk

# 인증
snyk auth

# 취약점 스캔
snyk test

# 자동 수정 (PR 생성)
snyk wizard

# 도커 이미지 스캔
snyk container test node:18-alpine

# 코드 스캔 (SAST)
snyk code test
```

```javascript
// .snyk 정책 파일
version: v1.22.1
ignore:
  'SNYK-JS-MINIMIST-559764':
    - '*':
        reason: 'Not used in production'
        expires: '2024-12-31T00:00:00.000Z'
patch: {}
```

### 2) Dependabot (GitHub)

```yaml
# .github/dependabot.yml
version: 2
updates:
  # npm 의존성 자동 업데이트
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
      day: "monday"
    open-pull-requests-limit: 10
    reviewers:
      - "security-team"
    labels:
      - "dependencies"
      - "security"
    # 취약점만 자동 수정
    auto-merge:
      dependency-type: "direct:production"
      update-type: "security"
  
  # Docker 이미지 업데이트
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
  
  # GitHub Actions 업데이트
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

### 3) npm audit in CI/CD

```yaml
# .github/workflows/security-audit.yml
name: Security Audit

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]
  schedule:
    # 매일 오전 9시 (UTC)
    - cron: '0 9 * * *'

jobs:
  audit:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
          cache: 'npm'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run npm audit
        run: |
          npm audit --audit-level=high
          if [ $? -ne 0 ]; then
            echo "::error::High severity vulnerabilities found!"
            exit 1
          fi
      
      - name: Run Snyk
        uses: snyk/actions/node@master
        env:
          SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
        with:
          args: --severity-threshold=high
      
      - name: Upload results to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: snyk.sarif
```

---

## 4. 안전한 패키지 선택 기준 ⭐️⭐️

### 체크리스트

```javascript
/*
1. 다운로드 수
   - 주간 다운로드 10,000+ 추천
   
2. 마지막 업데이트
   - 6개월 이내 업데이트 활발
   
3. 메인테이너
   - 복수의 메인테이너
   - 신뢰할 수 있는 조직/개인
   
4. 이슈/PR 응답 속도
   - 활발한 커뮤니티
   - 보안 이슈 빠른 대응
   
5. 의존성 수
   - 적을수록 좋음
   - 의존성 트리 깊이 확인
   
6. 라이선스
   - MIT, Apache 2.0 등 허용된 라이선스
   
7. 보안 정책
   - SECURITY.md 존재
   - 책임 있는 공개 (Responsible Disclosure)
   
8. 테스트 커버리지
   - 높은 코드 커버리지
   - CI/CD 배지
*/
```

### npm 패키지 조사 도구

```bash
# 패키지 정보 확인
npm info express

# 의존성 트리 확인
npm ls

# 특정 패키지의 의존성
npm ls express

# 중복 패키지 확인
npm dedupe

# 사용되지 않는 패키지 제거
npm prune
```

### Socket.dev 사용

```bash
# Socket CLI 설치
npm install -g @socketsecurity/cli

# 패키지 안전성 검사
socket npm install express

# 위험 패키지 탐지
socket npm audit
```

---

## 5. Lock 파일 무결성 검증 ⭐️⭐️

### Subresource Integrity (SRI) for CDN

```html
<!-- ❌ 위험: 무결성 검증 없음 -->
<script src="https://cdn.example.com/library.js"></script>

<!-- ✅ 안전: SRI 해시로 검증 -->
<script 
  src="https://cdn.example.com/library.js"
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
  crossorigin="anonymous">
</script>
```

### SRI 해시 생성

```bash
# 로컬 파일의 SRI 해시 생성
openssl dgst -sha384 -binary library.js | openssl base64 -A

# 온라인 도구
# https://www.srihash.org/
```

### npm/yarn에서 무결성 검증

```javascript
// package-lock.json의 integrity 필드 확인
{
  "node_modules/express": {
    "version": "4.18.2",
    "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
    "integrity": "sha512-5/PsL6iGPdfQ/lKM1UuielYgv3BUoJfz1aUwU9vHZ+J7gyvwdQXFEBIEIaxeGf0GIcreATNyBExtalisDbuMqQ=="
  }
}
```

---

## 6. Private Registry 사용 ⭐️⭐️

### Verdaccio (Private npm Registry)

```bash
# Verdaccio 설치
npm install -g verdaccio

# 실행
verdaccio

# .npmrc 설정
registry=http://localhost:4873/
```

```yaml
# verdaccio/config.yaml
storage: ./storage
auth:
  htpasswd:
    file: ./htpasswd
uplinks:
  npmjs:
    url: https://registry.npmjs.org/
packages:
  '@company/*':
    access: $authenticated
    publish: $authenticated
  '**':
    access: $all
    publish: $authenticated
    proxy: npmjs
```

### GitHub Packages

```bash
# .npmrc 설정
@mycompany:registry=https://npm.pkg.github.com
//npm.pkg.github.com/:_authToken=${GITHUB_TOKEN}
```

```json
// package.json
{
  "name": "@mycompany/my-package",
  "publishConfig": {
    "registry": "https://npm.pkg.github.com"
  }
}
```

---

## 7. 의존성 최소화 ⭐️⭐️⭐️

### 불필요한 패키지 제거

```javascript
// ❌ 과도한 의존성
import _ from 'lodash';  // 전체 라이브러리
import moment from 'moment';  // 매우 무거움

const result = _.uniq([1, 2, 2, 3]);
const date = moment().format('YYYY-MM-DD');

// ✅ 네이티브 또는 가벼운 대안
const result = [...new Set([1, 2, 2, 3])];
const date = new Date().toISOString().split('T')[0];

// ✅ 필요한 부분만 import
import uniq from 'lodash/uniq';
import dayjs from 'dayjs';  // moment 대안 (2KB vs 230KB)
```

### 번들 크기 분석

```bash
# webpack-bundle-analyzer
npm install --save-dev webpack-bundle-analyzer

# package.json
"scripts": {
  "analyze": "webpack-bundle-analyzer dist/stats.json"
}

# 실행
npm run build
npm run analyze
```

---

## 8. 보안 정책 수립 ⭐️⭐️

### SECURITY.md

```markdown
# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 5.1.x   | :white_check_mark: |
| 5.0.x   | :x:                |
| 4.0.x   | :white_check_mark: |
| < 4.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please send an email to security@example.com.

You should receive a response within 48 hours.

## Security Update Process

1. Security issue reported privately
2. Issue is verified and fixed
3. CVE is requested (if applicable)
4. Patch is released
5. Public disclosure

## Bug Bounty Program

We offer rewards for security vulnerabilities:
- Critical: $500 - $5,000
- High: $100 - $500
- Medium: $50 - $100
```

### 의존성 업데이트 정책

```javascript
/*
정책:
1. 보안 업데이트는 24시간 이내 적용
2. Major 버전 업데이트는 테스트 후 적용
3. 매주 월요일 의존성 검토
4. CI/CD에서 취약점 발견 시 배포 차단
5. 분기별 전체 의존성 감사

프로세스:
1. Dependabot PR 생성
2. 자동 테스트 실행
3. 보안 팀 검토
4. 승인 후 병합
5. 프로덕션 배포
*/
```

---

## 9. 실전 예제: 안전한 의존성 관리

### 프로젝트 초기 설정

```bash
#!/bin/bash
# init-secure-project.sh

# 1. 프로젝트 초기화
npm init -y

# 2. 보안 도구 설치
npm install --save-dev @socketsecurity/cli snyk

# 3. Git hooks 설정 (Husky)
npm install --save-dev husky
npx husky install
npx husky add .husky/pre-commit "npm audit"
npx husky add .husky/pre-push "npm test"

# 4. Dependabot 설정
mkdir -p .github
cat > .github/dependabot.yml << EOF
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
EOF

# 5. Security audit workflow
mkdir -p .github/workflows
cat > .github/workflows/security.yml << EOF
name: Security Audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
      - run: npm ci
      - run: npm audit --audit-level=high
EOF

echo "✅ 보안 프로젝트 설정 완료!"
```

### 주기적인 의존성 검토

```javascript
// scripts/audit-dependencies.js
const { execSync } = require('child_process');
const fs = require('fs');

function auditDependencies() {
  console.log('📦 의존성 검사 시작...\n');
  
  // 1. npm audit
  console.log('1️⃣ npm audit 실행');
  try {
    execSync('npm audit --json > audit-report.json', { stdio: 'inherit' });
  } catch (err) {
    console.error('⚠️ 취약점 발견!');
  }
  
  // 2. 오래된 패키지 확인
  console.log('\n2️⃣ 오래된 패키지 확인');
  execSync('npm outdated', { stdio: 'inherit' });
  
  // 3. 중복 패키지 확인
  console.log('\n3️⃣ 중복 패키지 확인');
  execSync('npm ls --all', { stdio: 'inherit' });
  
  // 4. Snyk 스캔
  console.log('\n4️⃣ Snyk 스캔');
  try {
    execSync('snyk test --json > snyk-report.json', { stdio: 'inherit' });
  } catch (err) {
    console.error('⚠️ Snyk 취약점 발견!');
  }
  
  console.log('\n✅ 의존성 검사 완료!');
  console.log('📊 보고서: audit-report.json, snyk-report.json');
}

auditDependencies();
```

---

## 베스트 프랙티스 요약

### 의존성 관리
- ✅ package-lock.json 커밋
- ✅ 정기적인 업데이트
- ✅ 취약점 자동 스캔
- ✅ Dependabot 활성화
- ✅ 의존성 최소화

### 보안 검증
- ✅ npm audit 주기적 실행
- ✅ Snyk/Socket 사용
- ✅ CI/CD에 보안 검사 통합
- ✅ Private registry 사용 고려

### 모니터링
- ✅ 실시간 알림 설정
- ✅ 보안 정책 문서화
- ✅ 버그 바운티 프로그램
- ✅ 분기별 전체 감사

---

## 결론

소프트웨어 공급망 보안은 현대 개발에서 필수적입니다. 단 하나의 취약한 의존성이 전체 시스템을 위험에 빠뜨릴 수 있습니다.

**핵심 원칙:**
1. **신뢰할 수 있는 출처**에서만 패키지 설치
2. **최신 상태 유지** (보안 패치 적용)
3. **최소 권한 원칙** (필요한 패키지만 설치)
4. **지속적인 모니터링** (자동화된 스캔)

공급망 보안은 한 번의 설정이 아닌 지속적인 프로세스입니다!
