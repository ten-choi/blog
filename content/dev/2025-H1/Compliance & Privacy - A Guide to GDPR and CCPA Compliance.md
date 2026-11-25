---
title: "Compliance & Privacy - A Guide to GDPR and CCPA Compliance"
labels: ["security","gdpr","compliance","privacy","data-protection","Archive"]
published: true
date: 2025-01-20T17:12:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "8928380236008962513"
source: "archive"
archivePath: "_archive/dev/security/compliance-privacy-guide-kr.md"
---

# Compliance & Privacy - A Guide to GDPR and CCPA Compliance

Complying with privacy regulations isn't optional. Violations bring huge fines and legal liability. This guide covers how to comply with the major regulations, including GDPR and CCPA.

---

## 1. GDPR (General Data Protection Regulation) ⭐️⭐️⭐️

### Concept

The EU's General Data Protection Regulation applies to every organization that processes the personal data of EU citizens.

**Core principles:**
- **Lawfulness**: clear consent is required
- **Purpose limitation**: state why data is collected
- **Minimization**: collect only the minimum data needed
- **Accuracy**: keep data accurate
- **Storage limitation**: keep data only as long as needed
- **Integrity and confidentiality**: process data securely

### Fines for Violations

- **Tier 1**: up to €10M or 2% of annual revenue
- **Tier 2**: up to €20M or 4% of annual revenue

### Rights of the Data Subject

```javascript
/*
1. Right to Access - see your own data
2. Right to Rectification - correct inaccurate data
3. Right to Erasure - the right to be forgotten
4. Right to Restriction - request limits on processing
5. Right to Data Portability - move your data
6. Right to Object - object to processing
7. Automated Decision-Making - refuse automated decisions
*/
```

### Implementing GDPR Compliance

#### 1) Cookie Consent

```javascript
// CookieConsent.js
import React, { useState, useEffect } from 'react';

export default function CookieConsent() {
  const [showBanner, setShowBanner] = useState(false);
  const [preferences, setPreferences] = useState({
    necessary: true,      // required (cannot be declined)
    functional: false,
    analytics: false,
    marketing: false
  });
  
  useEffect(() => {
    const consent = localStorage.getItem('cookieConsent');
    if (!consent) {
      setShowBanner(true);
    }
  }, []);
  
  const acceptAll = () => {
    const allAccepted = {
      necessary: true,
      functional: true,
      analytics: true,
      marketing: true
    };
    
    setPreferences(allAccepted);
    localStorage.setItem('cookieConsent', JSON.stringify(allAccepted));
    setShowBanner(false);
    
    // Enable Google Analytics
    if (window.gtag) {
      window.gtag('consent', 'update', {
        analytics_storage: 'granted'
      });
    }
  };
  
  const acceptSelected = () => {
    localStorage.setItem('cookieConsent', JSON.stringify(preferences));
    setShowBanner(false);
    
    if (window.gtag) {
      window.gtag('consent', 'update', {
        analytics_storage: preferences.analytics ? 'granted' : 'denied',
        ad_storage: preferences.marketing ? 'granted' : 'denied'
      });
    }
  };
  
  const rejectAll = () => {
    const onlyNecessary = {
      necessary: true,
      functional: false,
      analytics: false,
      marketing: false
    };
    
    localStorage.setItem('cookieConsent', JSON.stringify(onlyNecessary));
    setShowBanner(false);
  };
  
  if (!showBanner) return null;
  
  return (
    <div className="cookie-consent-banner">
      <h3>🍪 Cookie Consent</h3>
      <p>
        This website uses necessary and optional cookies. 
        See our <a href="/privacy-policy">Privacy Policy</a> for details.
      </p>
      
      <div className="cookie-options">
        <label>
          <input 
            type="checkbox" 
            checked={true} 
            disabled 
          />
          Necessary cookies (required)
        </label>
        
        <label>
          <input 
            type="checkbox" 
            checked={preferences.functional}
            onChange={(e) => setPreferences({
              ...preferences,
              functional: e.target.checked
            })}
          />
          Functional cookies
        </label>
        
        <label>
          <input 
            type="checkbox" 
            checked={preferences.analytics}
            onChange={(e) => setPreferences({
              ...preferences,
              analytics: e.target.checked
            })}
          />
          Analytics cookies
        </label>
        
        <label>
          <input 
            type="checkbox" 
            checked={preferences.marketing}
            onChange={(e) => setPreferences({
              ...preferences,
              marketing: e.target.checked
            })}
          />
          Marketing cookies
        </label>
      </div>
      
      <div className="button-group">
        <button onClick={rejectAll}>Necessary only</button>
        <button onClick={acceptSelected}>Allow selected</button>
        <button onClick={acceptAll}>Allow all</button>
      </div>
    </div>
  );
}
```

#### 2) Implementing the Right of Access

```javascript
// The user requests their own data
app.get('/api/user/data-export', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    
    // Gather all personal data
    const userData = await User.findById(userId);
    const orders = await Order.find({ userId });
    const reviews = await Review.find({ userId });
    const loginHistory = await LoginHistory.find({ userId });
    
    const exportData = {
      personalInfo: {
        name: userData.name,
        email: userData.email,
        phone: userData.phone,
        address: userData.address,
        dateOfBirth: userData.dateOfBirth,
        createdAt: userData.createdAt
      },
      orders: orders.map(order => ({
        orderId: order.id,
        date: order.createdAt,
        amount: order.totalAmount,
        items: order.items
      })),
      reviews: reviews.map(review => ({
        productId: review.productId,
        rating: review.rating,
        comment: review.comment,
        date: review.createdAt
      })),
      loginHistory: loginHistory.map(log => ({
        timestamp: log.createdAt,
        ipAddress: log.ipAddress,
        userAgent: log.userAgent
      }))
    };
    
    // Download as a JSON file
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="user-data-${userId}.json"`);
    res.json(exportData);
    
    // Log the request (audit trail)
    await AuditLog.create({
      userId,
      action: 'DATA_EXPORT',
      timestamp: new Date(),
      ipAddress: req.ip
    });
    
  } catch (err) {
    console.error('Data export failed:', err);
    res.status(500).json({ error: 'Failed to export data' });
  }
});
```

#### 3) Right to Be Forgotten

```javascript
// Fully delete a user account
app.delete('/api/user/account', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { password, reason } = req.body;
    
    // Confirm the password
    const user = await User.findById(userId);
    const isValid = await bcrypt.compare(password, user.password);
    
    if (!isValid) {
      return res.status(401).json({ error: 'Incorrect password' });
    }
    
    // Set a 30-day grace period (optional)
    await User.findByIdAndUpdate(userId, {
      deletionScheduledAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      status: 'PENDING_DELETION'
    });
    
    // To delete immediately instead
    // await deleteUserData(userId);
    
    // Log the deletion request
    await AuditLog.create({
      userId,
      action: 'ACCOUNT_DELETION_REQUEST',
      reason,
      timestamp: new Date()
    });
    
    res.json({ 
      message: 'Account deletion has been scheduled. Log in within 30 days to cancel.' 
    });
    
  } catch (err) {
    console.error('Account deletion failed:', err);
    res.status(500).json({ error: 'Failed to delete account' });
  }
});

// Run scheduled deletions (cron job)
async function deleteUserData(userId) {
  // 1. Delete the user record
  await User.findByIdAndDelete(userId);
  
  // 2. Delete related data
  await Order.deleteMany({ userId });
  await Review.deleteMany({ userId });
  await LoginHistory.deleteMany({ userId });
  await Session.deleteMany({ userId });
  
  // 3. Anonymize data you're legally required to retain
  await Invoice.updateMany(
    { userId },
    { 
      $set: { 
        userId: null,
        userName: 'DELETED_USER',
        userEmail: 'deleted@example.com'
      } 
    }
  );
  
  // 4. Delete from external services too
  await deleteFromEmailService(userId);
  await deleteFromAnalytics(userId);
  
  console.log(`All data for user ${userId} has been deleted`);
}
```

---

## 2. CCPA (California Consumer Privacy Act) ⭐️⭐️

### Concept

California's consumer privacy law applies to businesses that process the personal information of California residents.

### Consumer Rights Under the CCPA

```javascript
/*
1. Right to Know - see what information is collected/sold
2. Right to Delete - request deletion of personal information
3. Right to Opt-Out - opt out of the sale of data
4. Non-Discrimination - no discrimination for exercising these rights
*/
```

### Implementing "Do Not Sell My Info"

```javascript
// Manage Do Not Sell status
const dntSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true },
  doNotSell: { type: Boolean, default: false },
  updatedAt: { type: Date, default: Date.now }
});

const DoNotTrack = mongoose.model('DoNotTrack', dntSchema);

// "Do Not Sell" settings page
app.post('/api/privacy/do-not-sell', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const { doNotSell } = req.body;
    
    await DoNotTrack.findOneAndUpdate(
      { userId },
      { doNotSell, updatedAt: new Date() },
      { upsert: true }
    );
    
    // Notify third-party services
    if (doNotSell) {
      await notifyAdPartners(userId, 'OPT_OUT');
    }
    
    res.json({ message: 'Settings saved' });
    
  } catch (err) {
    res.status(500).json({ error: 'Failed to save settings' });
  }
});

// Check before selling data
async function canSellUserData(userId) {
  const dnt = await DoNotTrack.findOne({ userId });
  return !dnt || !dnt.doNotSell;
}
```

---

## 3. PCI-DSS (Payment Card Industry Data Security Standard) ⭐️⭐️⭐️

### Concept

The security standard every organization that handles credit card data must comply with.

### The 12 Requirements

```javascript
/*
1. Install and maintain a firewall
2. Change default passwords
3. Protect stored cardholder data
4. Encrypt data in transit
5. Protect against malware
6. Develop secure systems
7. Restrict access
8. Assign unique IDs
9. Restrict physical access
10. Track and monitor all access
11. Test security regularly
12. Maintain an information security policy
*/
```

### Processing Payments Safely

```javascript
// ❌ Never do this
const payment = {
  cardNumber: '1234-5678-9012-3456',  // never store in plain text!
  cvv: '123',                          // never store the CVV!
  expiryDate: '12/25'
};

// ✅ Use a PCI-certified service like Stripe/PayPal
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

app.post('/api/payment', authenticateToken, async (req, res) => {
  try {
    const { amount, currency } = req.body;
    
    // Create a Stripe Checkout session
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency,
          product_data: {
            name: 'Product Name'
          },
          unit_amount: amount
        },
        quantity: 1
      }],
      mode: 'payment',
      success_url: `${process.env.DOMAIN}/success`,
      cancel_url: `${process.env.DOMAIN}/cancel`,
      customer_email: req.user.email
    });
    
    // Payment details are stored only at Stripe;
    // our DB stores just the transaction ID
    await Payment.create({
      userId: req.user.id,
      stripeSessionId: session.id,
      amount,
      currency,
      status: 'PENDING'
    });
    
    res.json({ url: session.url });
    
  } catch (err) {
    console.error('Failed to create payment:', err);
    res.status(500).json({ error: 'Payment processing failed' });
  }
});

// Update payment status via webhook
app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  
  try {
    const event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET
    );
    
    if (event.type === 'checkout.session.completed') {
      const session = event.data.object;
      
      await Payment.findOneAndUpdate(
        { stripeSessionId: session.id },
        { status: 'COMPLETED' }
      );
    }
    
    res.json({ received: true });
    
  } catch (err) {
    console.error('Webhook error:', err);
    res.status(400).send(`Webhook Error: ${err.message}`);
  }
});
```

---

## 4. HIPAA (Health Insurance Portability and Accountability Act) ⭐️⭐️

### Concept

The US health information privacy law, which applies to every organization that handles protected health information (PHI).

### Protecting PHI (Protected Health Information)

```javascript
// Encrypting medical information
const crypto = require('crypto');

class PHIEncryption {
  constructor(encryptionKey) {
    this.algorithm = 'aes-256-gcm';
    this.key = Buffer.from(encryptionKey, 'hex');
  }
  
  encrypt(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return {
      encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex')
    };
  }
  
  decrypt(encrypted, iv, authTag) {
    const decipher = crypto.createDecipheriv(
      this.algorithm,
      this.key,
      Buffer.from(iv, 'hex')
    );
    
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }
}

// Usage
const patientSchema = new mongoose.Schema({
  patientId: String,
  encryptedData: String,
  iv: String,
  authTag: String,
  lastAccessedBy: String,
  lastAccessedAt: Date
});

const phiEncryption = new PHIEncryption(process.env.PHI_ENCRYPTION_KEY);

// Save patient information
app.post('/api/patients', authenticateToken, async (req, res) => {
  // Medical staff only
  if (!req.user.roles.includes('MEDICAL_STAFF')) {
    return res.status(403).json({ error: 'Permission denied' });
  }
  
  const { name, ssn, diagnosis, medications } = req.body;
  
  // Encrypt the PHI
  const sensitiveData = JSON.stringify({ name, ssn, diagnosis, medications });
  const { encrypted, iv, authTag } = phiEncryption.encrypt(sensitiveData);
  
  const patient = await Patient.create({
    patientId: generatePatientId(),
    encryptedData: encrypted,
    iv,
    authTag,
    lastAccessedBy: req.user.id,
    lastAccessedAt: new Date()
  });
  
  // Access log (audit trail is mandatory)
  await AuditLog.create({
    userId: req.user.id,
    action: 'PHI_CREATE',
    patientId: patient.patientId,
    timestamp: new Date()
  });
  
  res.json({ patientId: patient.patientId });
});
```

---

## 5. The Privacy Policy Page

### Privacy Policy Template

```markdown
# Privacy Policy

Last updated: 2024-01-01

## 1. Information We Collect

### Information collected automatically
- IP address
- Browser type and version
- Operating system
- Cookies and similar technologies

### Information you provide
- Name, email address
- Phone number
- Shipping address

## 2. How We Use Information

- Providing and improving the service
- Customer support
- Marketing and promotions (with consent)
- Security and fraud prevention

## 3. Information Sharing

Your personal information is not shared with third parties except:
- When required by law
- With partners needed to provide the service (AWS, Stripe, etc.)
- With your explicit consent

## 4. Data Retention

- Account information: 30 days after account deletion
- Order information: 5 years (tax law)
- Log data: 90 days

## 5. Your Rights

- Right of access: see your own data
- Right to rectification: correct inaccurate data
- Right to erasure: request deletion of your data
- Right to object: refuse processing

To exercise your rights, contact privacy@example.com.

## 6. Cookies

We don't use any cookies other than necessary ones without your consent.

## 7. Security

- TLS/SSL encryption
- Regular security audits
- Access control and monitoring

## 8. Contact

Privacy officer: privacy@example.com
```

---

## 6. Audit Trail

### Recording Every Access to Personal Data

```javascript
const auditLogSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  action: { 
    type: String, 
    enum: [
      'DATA_ACCESS',
      'DATA_EXPORT',
      'DATA_UPDATE',
      'DATA_DELETE',
      'ACCOUNT_DELETION_REQUEST',
      'PHI_ACCESS',
      'PAYMENT_PROCESSED'
    ],
    required: true
  },
  resourceType: String,
  resourceId: String,
  ipAddress: String,
  userAgent: String,
  timestamp: { type: Date, default: Date.now },
  details: mongoose.Schema.Types.Mixed
});

// Indexes for fast lookups
auditLogSchema.index({ userId: 1, timestamp: -1 });
auditLogSchema.index({ action: 1, timestamp: -1 });

const AuditLog = mongoose.model('AuditLog', auditLogSchema);

// Automatic logging via middleware
function auditMiddleware(action) {
  return async (req, res, next) => {
    const originalJson = res.json;
    
    res.json = function(data) {
      // Log only successful responses
      if (res.statusCode < 400) {
        AuditLog.create({
          userId: req.user?.id || 'anonymous',
          action,
          resourceType: req.params.resourceType,
          resourceId: req.params.id,
          ipAddress: req.ip,
          userAgent: req.get('user-agent'),
          details: {
            method: req.method,
            url: req.url,
            status: res.statusCode
          }
        }).catch(err => console.error('Failed to save audit log:', err));
      }
      
      originalJson.call(this, data);
    };
    
    next();
  };
}

// Usage
app.get('/api/user/data', authenticateToken, auditMiddleware('DATA_ACCESS'), async (req, res) => {
  // Fetch the data...
});
```

---

## Best Practices Summary

### GDPR/CCPA Compliance
- ✅ Obtain clear consent
- ✅ Implement a cookie banner
- ✅ Provide data export
- ✅ Provide account deletion
- ✅ Publish a privacy policy
- ✅ Appoint a DPO (Data Protection Officer)

### PCI-DSS Compliance
- ✅ Never store card data yourself
- ✅ Use Stripe/PayPal
- ✅ Use TLS/SSL
- ✅ Test security regularly

### Audit Trail
- ✅ Record every access to personal data
- ✅ Retain for at least 1 year
- ✅ Keep logs immutable
- ✅ Audit regularly

---

## Conclusion

Compliance isn't just about following the law; it's how you earn users' trust. Beyond the fines, damage to your brand can be the bigger cost of a violation.

**Recommended checklist:**
- [ ] Implement a cookie consent banner
- [ ] Write a privacy policy
- [ ] Data export feature
- [ ] Account deletion feature
- [ ] Audit logging system
- [ ] Regular compliance audits

Privacy protection is an investment, not a cost!
