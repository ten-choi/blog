---
title: "Authentication & Authorization - The Complete Guide"
labels: ["security","authentication","authorization","jwt","oauth","Archive"]
published: true
date: 2025-01-15T12:50:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "1359551630082924475"
source: "archive"
archivePath: "_archive/dev/security/authentication-security-guide-kr.md"
---

# Authentication & Authorization - The Complete Guide

Authentication and authorization are the front line of security. This guide covers how modern web applications can safely identify users and manage what they're allowed to do.

---

## 1. Authentication vs Authorization

### Concepts

**Authentication**: "Who are you?"
- The process of verifying a user's identity
- Login, biometrics, token verification, etc.

**Authorization**: "Are you allowed to do this?"
- The process of checking what an authenticated user is permitted to do
- Role-based access control, resource ownership checks, etc.

### A Real-World Example

```
Airport security checkpoint:
1. Authentication: ID check (confirming you're the person on the ticket)
2. Authorization: boarding pass check (confirming you're allowed on this flight)
```

---

## 2. JWT (JSON Web Token) ⭐️⭐️⭐️

### Concept

JWT is a token-based authentication method that uses a JSON object to transmit information securely.

**Structure**: `Header.Payload.Signature`

```javascript
// JWT example
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJ1c2VySWQiOiIxMjM0NSIsInJvbGUiOiJ1c2VyIn0.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### Implementation

**Issuing and verifying tokens**

```javascript
const jwt = require('jsonwebtoken');

// 1. Issue tokens on login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  // Authenticate the user
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: 'Invalid email or password' });
  }
  
  // Create the JWT
  const accessToken = jwt.sign(
    { 
      userId: user.id, 
      email: user.email,
      role: user.role 
    },
    process.env.JWT_SECRET,
    { expiresIn: '15m' }
  );
  
  const refreshToken = jwt.sign(
    { userId: user.id },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: '7d' }
  );
  
  // Store the refresh token in the DB
  await user.update({ refreshToken });
  
  res.json({ 
    accessToken,
    refreshToken,
    user: { id: user.id, email: user.email, role: user.role }
  });
});

// 2. Token verification middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication token required' });
  }
  
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ error: 'Token has expired' });
      }
      return res.status(403).json({ error: 'Invalid token' });
    }
    
    req.user = decoded;
    next();
  });
}

// 3. Issue a new access token with the refresh token
app.post('/api/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  
  if (!refreshToken) {
    return res.status(401).json({ error: 'Refresh token required' });
  }
  
  try {
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findById(decoded.userId);
    
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(403).json({ error: 'Invalid refresh token' });
    }
    
    const newAccessToken = jwt.sign(
      { userId: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '15m' }
    );
    
    res.json({ accessToken: newAccessToken });
  } catch (err) {
    return res.status(403).json({ error: 'Refresh token is not valid' });
  }
});

// 4. Logout (invalidate the refresh token)
app.post('/api/logout', authenticateToken, async (req, res) => {
  await User.findByIdAndUpdate(req.user.userId, { refreshToken: null });
  res.json({ message: 'Logged out' });
});

// Example of a protected route
app.get('/api/profile', authenticateToken, (req, res) => {
  res.json({ 
    userId: req.user.userId,
    email: req.user.email,
    role: req.user.role
  });
});
```

### Best Practices

- **Short expiration**: 15 minutes to 1 hour for access tokens
- **Use refresh tokens**: for long-lived sessions
- **Strong secret**: a random string of at least 256 bits
- **HTTPS only**: always send tokens over HTTPS
- **No sensitive data**: never put passwords or similar in the payload

---

## 3. OAuth 2.0 & Social Login ⭐️⭐️⭐️

### Concept

OAuth 2.0 is a standard protocol for delegating authorization so that a third-party application can access a user's resources.

### Implementing Google OAuth 2.0

```javascript
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

// 1. Configure Passport
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    try {
      // Look up an existing user
      let user = await User.findOne({ googleId: profile.id });
      
      if (!user) {
        // Create a new user
        user = await User.create({
          googleId: profile.id,
          email: profile.emails[0].value,
          name: profile.displayName,
          avatar: profile.photos[0].value
        });
      }
      
      return done(null, user);
    } catch (err) {
      return done(err, null);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  const user = await User.findById(id);
  done(null, user);
});

// 2. Set up the routes
app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { 
    failureRedirect: '/login',
    session: false // when using JWT
  }),
  (req, res) => {
    // Issue a JWT
    const token = jwt.sign(
      { userId: req.user.id, email: req.user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    // Redirect to the client (with the token)
    res.redirect(`${process.env.CLIENT_URL}/auth/callback?token=${token}`);
  }
);
```

---

## 4. Session-Based Authentication ⭐️⭐️

### Concept

The server stores the user's information and hands the client only a session ID.

### Implementation

```javascript
const session = require('express-session');
const RedisStore = require('connect-redis')(session);
const redis = require('redis');

// Create the Redis client
const redisClient = redis.createClient({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT
});

// Session configuration
app.use(session({
  store: new RedisStore({ client: redisClient }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // HTTPS only
    maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
    sameSite: 'strict'
  }
}));

// Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: 'Authentication failed' });
  }
  
  // Store user info in the session
  req.session.userId = user.id;
  req.session.email = user.email;
  req.session.role = user.role;
  
  res.json({ message: 'Login successful', user: { id: user.id, email: user.email } });
});

// Authentication check middleware
function requireAuth(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Login required' });
  }
  next();
}

// Logout
app.post('/api/logout', requireAuth, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Logout failed' });
    }
    res.clearCookie('connect.sid');
    res.json({ message: 'Logout successful' });
  });
});
```

### JWT vs Session

| Feature | JWT | Session |
|------|-----|---------|
| Stored on | Client | Server (Redis/DB) |
| Stateless | O | X |
| Scalability | Good | Moderate |
| Revoking tokens | Hard | Easy |
| Size | Large | Small (just the session ID) |
| Best for | Microservices, SPAs | Traditional web apps |

---

## 5. Multi-Factor Authentication (MFA/2FA) ⭐️⭐️⭐️

### Concept

Strengthens security by requiring an additional factor on top of the password.

### Implementing TOTP (Time-based One-Time Password)

```javascript
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

// 1. Start MFA setup
app.post('/api/mfa/setup', authenticateToken, async (req, res) => {
  const user = await User.findById(req.user.userId);
  
  // Generate the TOTP secret
  const secret = speakeasy.generateSecret({
    name: `MyApp (${user.email})`,
    issuer: 'MyApp'
  });
  
  // Save temporarily (persist for real after confirmation)
  user.tempMfaSecret = secret.base32;
  await user.save();
  
  // Generate the QR code
  const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
  
  res.json({
    secret: secret.base32,
    qrCode: qrCodeUrl
  });
});

// 2. Confirm MFA setup
app.post('/api/mfa/verify-setup', authenticateToken, async (req, res) => {
  const { token } = req.body;
  const user = await User.findById(req.user.userId);
  
  // Verify the code the user entered
  const verified = speakeasy.totp.verify({
    secret: user.tempMfaSecret,
    encoding: 'base32',
    token,
    window: 2 // allow for clock drift
  });
  
  if (verified) {
    user.mfaSecret = user.tempMfaSecret;
    user.mfaEnabled = true;
    user.tempMfaSecret = null;
    await user.save();
    
    res.json({ message: 'MFA has been enabled' });
  } else {
    res.status(400).json({ error: 'Invalid code' });
  }
});

// 3. Verify MFA on login
app.post('/api/login', async (req, res) => {
  const { email, password, mfaToken } = req.body;
  
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: 'Authentication failed' });
  }
  
  // If MFA is enabled
  if (user.mfaEnabled) {
    if (!mfaToken) {
      return res.status(200).json({ 
        requireMfa: true,
        message: 'Please enter your MFA code'
      });
    }
    
    // Verify the MFA code
    const verified = speakeasy.totp.verify({
      secret: user.mfaSecret,
      encoding: 'base32',
      token: mfaToken,
      window: 2
    });
    
    if (!verified) {
      return res.status(401).json({ error: 'Invalid MFA code' });
    }
  }
  
  // Issue the JWT
  const token = jwt.sign(
    { userId: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
  
  res.json({ token });
});
```

---

## 6. Role-Based Access Control (RBAC) ⭐️⭐️⭐️

### Concept

Users are assigned roles, and each role is granted a set of permissions.

### Implementation

```javascript
// Define roles and permissions
const ROLES = {
  ADMIN: 'admin',
  MANAGER: 'manager',
  USER: 'user',
  GUEST: 'guest'
};

const PERMISSIONS = {
  [ROLES.ADMIN]: ['read', 'write', 'delete', 'manage_users'],
  [ROLES.MANAGER]: ['read', 'write', 'delete'],
  [ROLES.USER]: ['read', 'write'],
  [ROLES.GUEST]: ['read']
};

// Permission check middleware
function requirePermission(permission) {
  return (req, res, next) => {
    const userRole = req.user.role;
    const userPermissions = PERMISSIONS[userRole] || [];
    
    if (!userPermissions.includes(permission)) {
      return res.status(403).json({ 
        error: 'You do not have permission to perform this action',
        required: permission,
        userRole
      });
    }
    
    next();
  };
}

// Role check middleware
function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ 
        error: 'Access denied',
        requiredRoles: roles,
        userRole: req.user.role
      });
    }
    next();
  };
}

// Usage
app.delete('/api/users/:id', 
  authenticateToken,
  requirePermission('delete'),
  async (req, res) => {
    // Deletion logic
  }
);

app.get('/api/admin/dashboard',
  authenticateToken,
  requireRole(ROLES.ADMIN, ROLES.MANAGER),
  (req, res) => {
    res.json({ message: 'Admin Dashboard' });
  }
);
```

---

## 7. Attribute-Based Access Control (ABAC) ⭐️⭐️

### Concept

Permissions are decided dynamically based on user attributes, resource attributes, environment attributes, and so on.

### Implementation

```javascript
// Verify resource ownership
function checkOwnership(req, res, next) {
  const resourceId = req.params.id;
  const userId = req.user.userId;
  
  db.documents.findById(resourceId).then(document => {
    // Allow if the user is the owner or an admin
    if (document.ownerId === userId || req.user.role === 'admin') {
      req.document = document;
      return next();
    }
    
    res.status(403).json({ error: 'You do not have permission to access this document' });
  });
}

// Conditional permission check
function checkDocumentAccess(req, res, next) {
  const document = req.document;
  const user = req.user;
  
  // Public documents are open to everyone
  if (document.visibility === 'public') {
    return next();
  }
  
  // Private documents: owner only
  if (document.visibility === 'private' && document.ownerId === user.userId) {
    return next();
  }
  
  // Team documents: members of the same team only
  if (document.visibility === 'team' && document.teamId === user.teamId) {
    return next();
  }
  
  res.status(403).json({ error: 'Access denied' });
}

// Usage
app.get('/api/documents/:id',
  authenticateToken,
  checkOwnership,
  checkDocumentAccess,
  (req, res) => {
    res.json(req.document);
  }
);
```

---

## 8. Password Security ⭐️⭐️⭐️

### Password Hashing

```javascript
const bcrypt = require('bcrypt');
const argon2 = require('argon2');

// Using bcrypt (recommended)
async function hashPassword(password) {
  const saltRounds = 12; // higher = more secure, but slower
  return await bcrypt.hash(password, saltRounds);
}

async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}

// Using Argon2 (stronger)
async function hashPasswordArgon2(password) {
  return await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 2 ** 16, // 64MB
    timeCost: 3,
    parallelism: 1
  });
}

async function verifyPasswordArgon2(password, hash) {
  return await argon2.verify(hash, password);
}

// Sign-up
app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;
  
  // Check password strength
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters long' });
  }
  
  const passwordHash = await hashPassword(password);
  
  const user = await User.create({
    email,
    passwordHash
  });
  
  res.status(201).json({ message: 'Sign-up successful', userId: user.id });
});
```

### Password Policy

```javascript
const passwordValidator = require('password-validator');

const schema = new passwordValidator();

schema
  .is().min(8)                                    // at least 8 characters
  .is().max(100)                                  // at most 100 characters
  .has().uppercase()                              // contains uppercase
  .has().lowercase()                              // contains lowercase
  .has().digits(1)                                // at least 1 digit
  .has().symbols()                                // contains a special character
  .has().not().spaces()                           // no spaces
  .is().not().oneOf(['Password123', 'Admin123']); // block common passwords

function validatePassword(password) {
  const result = schema.validate(password, { details: true });
  
  if (result === true) {
    return { valid: true };
  }
  
  return { 
    valid: false, 
    errors: result.map(err => err.message)
  };
}
```

---

## 9. Account Security

### Brute-Force Protection

```javascript
const rateLimit = require('express-rate-limit');

// Limit login attempts
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // up to 5 attempts
  message: 'Too many login attempts. Please try again in 15 minutes.',
  standardHeaders: true,
  legacyHeaders: false
});

app.post('/api/login', loginLimiter, async (req, res) => {
  // Login logic
});

// Track failed logins per IP
const loginAttempts = new Map();

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const ip = req.ip;
  const key = `${ip}:${email}`;
  
  // Check the failure count
  const attempts = loginAttempts.get(key) || 0;
  
  if (attempts >= 5) {
    return res.status(429).json({ 
      error: 'Account temporarily locked. Please try again in 15 minutes.' 
    });
  }
  
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    // Increment the failure count
    loginAttempts.set(key, attempts + 1);
    
    // Auto-clear after 15 minutes
    setTimeout(() => loginAttempts.delete(key), 15 * 60 * 1000);
    
    return res.status(401).json({ error: 'Authentication failed' });
  }
  
  // Reset the failure count on success
  loginAttempts.delete(key);
  
  // Issue the token
  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});
```

### Account Lockout

```javascript
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  
  const user = await User.findOne({ email });
  
  // Check whether the account is locked
  if (user && user.lockedUntil && user.lockedUntil > new Date()) {
    const remainingTime = Math.ceil((user.lockedUntil - new Date()) / 1000 / 60);
    return res.status(403).json({ 
      error: `Account locked. Please try again in ${remainingTime} minutes.` 
    });
  }
  
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    if (user) {
      user.loginAttempts += 1;
      
      // Lock for 30 minutes after 5 failures
      if (user.loginAttempts >= 5) {
        user.lockedUntil = new Date(Date.now() + 30 * 60 * 1000);
        await user.save();
        return res.status(403).json({ error: 'Account locked for 30 minutes after 5 failed attempts.' });
      }
      
      await user.save();
    }
    
    return res.status(401).json({ error: 'Authentication failed' });
  }
  
  // Reset on successful login
  user.loginAttempts = 0;
  user.lockedUntil = null;
  user.lastLoginAt = new Date();
  await user.save();
  
  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.json({ token });
});
```

---

## Best Practices Summary

### Authentication
- ✅ Hash passwords with bcrypt/Argon2
- ✅ Keep JWT expiration short (15 minutes to 1 hour)
- ✅ Use refresh tokens for long-lived sessions
- ✅ Send tokens over HTTPS only
- ✅ Enable MFA (especially for admins)
- ✅ Defend against brute-force attacks
- ✅ Have an account lockout policy

### Authorization
- ✅ Apply the principle of least privilege
- ✅ Manage access by role with RBAC
- ✅ Verify resource ownership
- ✅ Return 403 when permission is missing
- ✅ Return 401 when login is required

### Security
- ✅ Store tokens in httpOnly cookies instead of localStorage
- ✅ Use CSRF tokens (when using cookies)
- ✅ Prevent API abuse with rate limiting
- ✅ Log security events
- ✅ Run regular security audits

---

## Conclusion

Authentication and authorization are the front line of security. There are many options, including JWT, OAuth, sessions, and MFA, but you need to understand the trade-offs of each and pick what fits your project.

**Recommended combinations:**
- **SPA/mobile apps**: JWT + refresh token + MFA
- **Traditional web apps**: session + MFA
- **Microservices**: JWT + OAuth 2.0
- **Enterprise**: SAML 2.0 + MFA

Security is an ongoing process. Keep an eye on the latest security trends and run security audits regularly.
