---
title: "Supply Chain Security - A Guide to Dependency Security"
labels: ["security","supply-chain","dependencies","vulnerability","open-source","Archive"]
published: true
date: 2025-02-27T10:12:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "3581658808689764283"
source: "archive"
archivePath: "_archive/dev/security/supply-chain-security-guide-kr.md"
---

# Supply Chain Security - A Guide to Dependency Security

Software supply chain attacks are one of the fastest-growing security threats today. On average, about 80% of an application's code comes from open-source libraries. This guide covers how to manage your dependencies safely.

---

## 1. What Is a Supply Chain Attack? ⭐️⭐️⭐️

### Real-World Incidents

#### 1) The event-stream attack (2018)
```javascript
// A package with hidden malicious code
// Code that stole cryptocurrency wallets was injected into event-stream@3.3.6
```

Impact: 2M+ downloads, compromised the Copay bitcoin wallet

#### 2) The colors.js / faker.js incident (2022)
```javascript
// The developer intentionally added malicious code
// An infinite loop that brought applications down
while(true) {
  console.log('LIBERTY LIBERTY LIBERTY');
}
```

#### 3) The SolarWinds attack (2020)
A compromised build system distributed malicious code to 18,000 organizations

### Types of Supply Chain Attacks

```javascript
/*
1. Direct Dependency Compromise
   - Uploading malicious packages
   - Typosquatting

2. Transitive Dependency Attack
   - Compromising a dependency's dependency
   - Exploiting deep dependency trees

3. Account Takeover
   - Hacking a maintainer's account
   - Publishing malicious updates

4. Build System Compromise
   - Attacking the CI/CD pipeline
   - Injecting malicious code during deployment
*/
```

---

## 2. npm/yarn Dependency Security ⭐️⭐️⭐️

### Secure package.json Settings

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

### Using npm audit

```bash
# Check for vulnerabilities
npm audit

# Auto-fix (minor/patch versions only)
npm audit fix

# Include risky updates (careful!)
npm audit fix --force

# Only check at or above a given severity
npm audit --audit-level=high

# Output as JSON
npm audit --json
```

### Why package-lock.json Matters

```json
// package-lock.json pins exact versions
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

**❌ Never do this:**
```bash
# Don't delete package-lock.json!
rm package-lock.json

# Don't add it to .gitignore!
package-lock.json
```

### Preventing Typosquatting

```javascript
// ❌ Dangerous: installing a malicious package because of a typo
npm install experss  // typo of express
npm install reqeust  // typo of request
npm install loadsh   // typo of lodash

// ✅ Safe: always check the official docs
// https://www.npmjs.com/package/express
npm install express
```

---

## 3. Automated Vulnerability Scanning ⭐️⭐️⭐️

### 1) Snyk

```bash
# Install the Snyk CLI
npm install -g snyk

# Authenticate
snyk auth

# Scan for vulnerabilities
snyk test

# Auto-fix (creates a PR)
snyk wizard

# Scan a Docker image
snyk container test node:18-alpine

# Scan code (SAST)
snyk code test
```

```javascript
// .snyk policy file
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
  # Automatic npm dependency updates
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
    # Auto-fix vulnerabilities only
    auto-merge:
      dependency-type: "direct:production"
      update-type: "security"
  
  # Docker image updates
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
  
  # GitHub Actions updates
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
    # Every day at 9 AM (UTC)
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

## 4. How to Choose Safe Packages ⭐️⭐️

### Checklist

```javascript
/*
1. Download count
   - 10,000+ weekly downloads recommended

2. Last update
   - Actively updated within the last 6 months

3. Maintainers
   - More than one maintainer
   - A trustworthy organization/individual

4. Issue/PR response time
   - An active community
   - Quick response to security issues

5. Number of dependencies
   - The fewer the better
   - Check how deep the dependency tree goes

6. License
   - Permissive licenses such as MIT or Apache 2.0

7. Security policy
   - Has a SECURITY.md
   - Responsible Disclosure

8. Test coverage
   - High code coverage
   - CI/CD badges
*/
```

### Tools for Inspecting npm Packages

```bash
# Show package info
npm info express

# Show the dependency tree
npm ls

# Dependencies of a specific package
npm ls express

# Deduplicate packages
npm dedupe

# Remove unused packages
npm prune
```

### Using Socket.dev

```bash
# Install the Socket CLI
npm install -g @socketsecurity/cli

# Check a package's safety
socket npm install express

# Detect risky packages
socket npm audit
```

---

## 5. Verifying Lock File Integrity ⭐️⭐️

### Subresource Integrity (SRI) for CDN

```html
<!-- ❌ Dangerous: no integrity check -->
<script src="https://cdn.example.com/library.js"></script>

<!-- ✅ Safe: verified with an SRI hash -->
<script 
  src="https://cdn.example.com/library.js"
  integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
  crossorigin="anonymous">
</script>
```

### Generating an SRI Hash

```bash
# Generate an SRI hash for a local file
openssl dgst -sha384 -binary library.js | openssl base64 -A

# Online tool
# https://www.srihash.org/
```

### Integrity Verification in npm/yarn

```javascript
// Check the integrity field in package-lock.json
{
  "node_modules/express": {
    "version": "4.18.2",
    "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
    "integrity": "sha512-5/PsL6iGPdfQ/lKM1UuielYgv3BUoJfz1aUwU9vHZ+J7gyvwdQXFEBIEIaxeGf0GIcreATNyBExtalisDbuMqQ=="
  }
}
```

---

## 6. Using a Private Registry ⭐️⭐️

### Verdaccio (Private npm Registry)

```bash
# Install Verdaccio
npm install -g verdaccio

# Run it
verdaccio

# .npmrc setting
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
# .npmrc setting
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

## 7. Minimizing Dependencies ⭐️⭐️⭐️

### Removing Unnecessary Packages

```javascript
// ❌ Too many dependencies
import _ from 'lodash';  // the whole library
import moment from 'moment';  // very heavy

const result = _.uniq([1, 2, 2, 3]);
const date = moment().format('YYYY-MM-DD');

// ✅ Native or lightweight alternatives
const result = [...new Set([1, 2, 2, 3])];
const date = new Date().toISOString().split('T')[0];

// ✅ Import only what you need
import uniq from 'lodash/uniq';
import dayjs from 'dayjs';  // moment alternative (2KB vs 230KB)
```

### Analyzing Bundle Size

```bash
# webpack-bundle-analyzer
npm install --save-dev webpack-bundle-analyzer

# package.json
"scripts": {
  "analyze": "webpack-bundle-analyzer dist/stats.json"
}

# Run it
npm run build
npm run analyze
```

---

## 8. Establishing a Security Policy ⭐️⭐️

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

### Dependency Update Policy

```javascript
/*
Policy:
1. Apply security updates within 24 hours
2. Apply major version updates only after testing
3. Review dependencies every Monday
4. Block deployment when CI/CD finds a vulnerability
5. Full dependency audit every quarter

Process:
1. Dependabot opens a PR
2. Automated tests run
3. Security team reviews
4. Merge after approval
5. Deploy to production
*/
```

---

## 9. Hands-On Example: Managing Dependencies Safely

### Initial Project Setup

```bash
#!/bin/bash
# init-secure-project.sh

# 1. Initialize the project
npm init -y

# 2. Install security tools
npm install --save-dev @socketsecurity/cli snyk

# 3. Set up Git hooks (Husky)
npm install --save-dev husky
npx husky install
npx husky add .husky/pre-commit "npm audit"
npx husky add .husky/pre-push "npm test"

# 4. Configure Dependabot
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

echo "✅ Secure project setup complete!"
```

### Regular Dependency Reviews

```javascript
// scripts/audit-dependencies.js
const { execSync } = require('child_process');
const fs = require('fs');

function auditDependencies() {
  console.log('📦 Starting dependency check...\n');
  
  // 1. npm audit
  console.log('1️⃣ Running npm audit');
  try {
    execSync('npm audit --json > audit-report.json', { stdio: 'inherit' });
  } catch (err) {
    console.error('⚠️ Vulnerabilities found!');
  }
  
  // 2. Check for outdated packages
  console.log('\n2️⃣ Checking for outdated packages');
  execSync('npm outdated', { stdio: 'inherit' });
  
  // 3. Check for duplicate packages
  console.log('\n3️⃣ Checking for duplicate packages');
  execSync('npm ls --all', { stdio: 'inherit' });
  
  // 4. Snyk scan
  console.log('\n4️⃣ Snyk scan');
  try {
    execSync('snyk test --json > snyk-report.json', { stdio: 'inherit' });
  } catch (err) {
    console.error('⚠️ Snyk found vulnerabilities!');
  }
  
  console.log('\n✅ Dependency check complete!');
  console.log('📊 Reports: audit-report.json, snyk-report.json');
}

auditDependencies();
```

---

## Best Practices Summary

### Dependency Management
- ✅ Commit package-lock.json
- ✅ Update regularly
- ✅ Scan for vulnerabilities automatically
- ✅ Enable Dependabot
- ✅ Minimize dependencies

### Security Verification
- ✅ Run npm audit regularly
- ✅ Use Snyk/Socket
- ✅ Integrate security checks into CI/CD
- ✅ Consider a private registry

### Monitoring
- ✅ Set up real-time alerts
- ✅ Document your security policy
- ✅ Bug bounty program
- ✅ Full audit every quarter

---

## Conclusion

Software supply chain security is essential in modern development. A single vulnerable dependency can put your entire system at risk.

**Core principles:**
1. Install packages only from **trusted sources**
2. **Stay up to date** (apply security patches)
3. **Principle of least privilege** (install only the packages you need)
4. **Continuous monitoring** (automated scans)

Supply chain security isn't a one-time setup — it's an ongoing process!
