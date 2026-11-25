---
title: "Secrets & Key Management - Keeping Sensitive Data Safe"
labels: ["security","secrets","credentials","vault","aws","Archive"]
published: true
date: 2025-02-16T12:26:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "8306914439790755384"
source: "archive"
archivePath: "_archive/dev/security/secrets-management-guide-kr.md"
---

# Secrets & Key Management - Keeping Sensitive Data Safe

Leaking sensitive information (secrets) such as API keys, database passwords, and encryption keys leads to serious security incidents. This guide covers how to store and manage secrets safely.

---

## 1. What You Must Never Do ❌

### Hardcoding in code

```javascript
// ❌ Never do this!
const API_KEY = 'sk-1234567890abcdefghijklmnop';
const DB_PASSWORD = 'MyS3cr3tP@ssw0rd!';
const JWT_SECRET = 'super-secret-key-123';
const STRIPE_SECRET = 'sk_live_51H...';

// Database connection
mongoose.connect('mongodb://admin:password123@localhost:27017/mydb');

// API call
fetch('https://api.example.com/data', {
  headers: { 'Authorization': 'Bearer sk-1234567890abcdef' }
});
```

**Why it's dangerous:**
- Push to GitHub and it's public to the whole world
- It stays in your Git history forever
- Automated bots detect it within seconds
- It can turn into a security incident immediately

### Committing to Git

```javascript
// ❌ Committing config.js to Git
module.exports = {
  database: {
    host: 'prod-db.example.com',
    user: 'admin',
    password: 'Pr0dP@ssw0rd!',  // Exposed!
    port: 5432
  },
  apiKeys: {
    stripe: 'sk_live_...',      // Exposed!
    sendgrid: 'SG.abc123...',   // Exposed!
    aws: {
      accessKeyId: 'AKIA...',   // Exposed!
      secretAccessKey: '...'    // Exposed!
    }
  }
};
```

### Exposing secrets on the client side

```javascript
// ❌ Including an API key in frontend code
const API_KEY = 'AIzaSyC-xxxxxxxxxxxxxxxxxxx'; // Visible in the browser!

// ❌ Embedding it directly in HTML
<script>
  const config = {
    apiKey: 'sk-1234567890abcdef'  // Visible via View Source!
  };
</script>
```

---

## 2. Environment Variables ⭐️⭐️⭐️

### Basic Usage

**Create a .env file**

```env
# .env file
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

**Add it to .gitignore**

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

**Use dotenv**

```javascript
// app.js
require('dotenv').config();

// Use environment variables
const dbConfig = {
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
};

const jwtSecret = process.env.JWT_SECRET;
const stripeKey = process.env.STRIPE_SECRET_KEY;

// Validate required environment variables
const requiredEnvVars = [
  'DB_PASSWORD',
  'JWT_SECRET',
  'STRIPE_SECRET_KEY'
];

for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`❌ Required environment variable ${envVar} is not set!`);
    process.exit(1);
  }
}
```

### Provide a .env.example

```env
# .env.example (safe to commit to Git)
NODE_ENV=development
PORT=3000

# Database (example for local development)
DB_HOST=localhost
DB_PORT=5432
DB_USER=myapp_dev
DB_PASSWORD=change_this_password
DB_NAME=myapp_development

# JWT
JWT_SECRET=generate_a_random_256_bit_key
JWT_EXPIRES_IN=1h

# API Keys (real keys are shared separately)
STRIPE_SECRET_KEY=sk_test_...
SENDGRID_API_KEY=your_sendgrid_key_here
```

---

## 3. AWS Secrets Manager ⭐️⭐️⭐️

### Concept

AWS Secrets Manager is a managed service that lets you securely store and rotate database credentials, API keys, passwords, and more.

### Creating a Secret (AWS CLI)

```bash
# Create a secret
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

# Read a secret
aws secretsmanager get-secret-value \
  --secret-id myapp/production/database

# Update a secret
aws secretsmanager update-secret \
  --secret-id myapp/production/database \
  --secret-string '{"username":"admin","password":"NewPassword123"}'

# Delete a secret (30-day recovery window)
aws secretsmanager delete-secret \
  --secret-id myapp/production/database \
  --recovery-window-in-days 30
```

### Using It in Node.js

```javascript
const AWS = require('aws-sdk');

// AWS SDK setup
const secretsManager = new AWS.SecretsManager({
  region: process.env.AWS_REGION || 'us-east-1'
});

// Fetch a secret
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
    console.error(`Failed to fetch secret ${secretName}:`, err);
    throw err;
  }
}

// Improve performance with caching
const secretCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5 minutes

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

// Usage example
async function initApp() {
  // Database settings
  const dbSecrets = await getCachedSecret('myapp/production/database');
  
  const dbConnection = await mongoose.connect(
    `mongodb://${dbSecrets.username}:${dbSecrets.password}@${dbSecrets.host}:${dbSecrets.port}/${dbSecrets.database}`
  );
  
  // API keys
  const apiSecrets = await getCachedSecret('myapp/production/api-keys');
  const stripeKey = apiSecrets.stripe;
  const sendgridKey = apiSecrets.sendgrid;
  
  console.log('✅ Secrets loaded');
  
  // Start the server
  app.listen(3000);
}

initApp().catch(err => {
  console.error('App initialization failed:', err);
  process.exit(1);
});
```

### Automatic Rotation

```javascript
// Rotate passwords automatically with a Lambda function
exports.handler = async (event) => {
  const { SecretId, Token, Step } = event;
  
  switch (Step) {
    case 'createSecret':
      // Generate a new password
      const newPassword = generateSecurePassword();
      await secretsManager.putSecretValue({
        SecretId,
        ClientRequestToken: Token,
        SecretString: JSON.stringify({ password: newPassword }),
        VersionStages: ['AWSPENDING']
      }).promise();
      break;
      
    case 'setSecret':
      // Set the new password in the database
      const pending = await getSecretVersion(SecretId, 'AWSPENDING');
      await updateDatabasePassword(pending.password);
      break;
      
    case 'testSecret':
      // Test the connection with the new password
      const test = await getSecretVersion(SecretId, 'AWSPENDING');
      await testDatabaseConnection(test);
      break;
      
    case 'finishSecret':
      // Promote the new password to the current version
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

### Concept

HashiCorp Vault is an enterprise-grade secrets management tool that offers dynamic secret generation, encryption as a service, audit logging, and more.

### Installing and Starting Vault

```bash
# Install Vault (macOS)
brew install vault

# Start in dev mode
vault server -dev

# Set environment variables
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='<Root Token>'

# Store a secret
vault kv put secret/myapp/database \
  username=admin \
  password=MyS3cur3P@ssw0rd \
  host=localhost \
  port=5432

# Read a secret
vault kv get secret/myapp/database

# Delete a secret
vault kv delete secret/myapp/database
```

### Using It in Node.js

```javascript
const vault = require('node-vault')({
  endpoint: process.env.VAULT_ADDR || 'http://127.0.0.1:8200',
  token: process.env.VAULT_TOKEN
});

// Read a secret
async function getVaultSecret(path) {
  try {
    const result = await vault.read(path);
    return result.data.data; // KV v2 engine
  } catch (err) {
    console.error(`Failed to read ${path} from Vault:`, err);
    throw err;
  }
}

// Write a secret
async function setVaultSecret(path, data) {
  try {
    await vault.write(path, { data });
    console.log(`✅ Secret saved: ${path}`);
  } catch (err) {
    console.error(`Failed to save ${path} to Vault:`, err);
    throw err;
  }
}

// Dynamic database credentials
async function getDynamicDbCredentials() {
  try {
    // Vault generates temporary DB credentials
    const creds = await vault.read('database/creds/my-role');
    
    return {
      username: creds.data.username,
      password: creds.data.password,
      leaseId: creds.lease_id,
      leaseDuration: creds.lease_duration // In seconds
    };
  } catch (err) {
    console.error('Failed to generate dynamic credentials:', err);
    throw err;
  }
}

// Renew a lease
async function renewLease(leaseId) {
  await vault.write(`sys/leases/renew`, {
    lease_id: leaseId,
    increment: 3600 // Extend by 1 hour
  });
}

// Usage example
async function initApp() {
  // Database settings
  const dbConfig = await getVaultSecret('secret/data/myapp/database');
  
  // Or use dynamic credentials
  const dynamicCreds = await getDynamicDbCredentials();
  
  const db = await connectDatabase({
    host: dbConfig.host,
    username: dynamicCreds.username,
    password: dynamicCreds.password
  });
  
  // Renew the lease automatically
  setInterval(() => {
    renewLease(dynamicCreds.leaseId);
  }, (dynamicCreds.leaseDuration - 300) * 1000); // Renew 5 minutes before expiry
  
  app.listen(3000);
}
```

### Vault Policy (Access Control)

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
# Apply the policy
vault policy write myapp-policy myapp-policy.hcl

# Create a token
vault token create -policy=myapp-policy -ttl=24h
```

---

## 5. Azure Key Vault ⭐️⭐️⭐️

### Using It in Node.js

```javascript
const { SecretClient } = require('@azure/keyvault-secrets');
const { DefaultAzureCredential } = require('@azure/identity');

const credential = new DefaultAzureCredential();
const vaultName = process.env.KEY_VAULT_NAME;
const vaultUrl = `https://${vaultName}.vault.azure.net`;

const client = new SecretClient(vaultUrl, credential);

// Create a secret
async function setSecret(name, value) {
  await client.setSecret(name, value);
  console.log(`✅ Secret "${name}" saved`);
}

// Read a secret
async function getSecret(name) {
  try {
    const secret = await client.getSecret(name);
    return secret.value;
  } catch (err) {
    console.error(`Could not fetch secret "${name}":`, err);
    throw err;
  }
}

// List secrets
async function listSecrets() {
  const secrets = [];
  for await (const secretProperties of client.listPropertiesOfSecrets()) {
    secrets.push(secretProperties.name);
  }
  return secrets;
}

// Delete a secret
async function deleteSecret(name) {
  const poller = await client.beginDeleteSecret(name);
  await poller.pollUntilDone();
  console.log(`✅ Secret "${name}" deleted`);
}

// Usage example
async function initApp() {
  const dbPassword = await getSecret('database-password');
  const apiKey = await getSecret('stripe-api-key');
  
  // Connect to the database
  await connectDatabase({
    password: dbPassword
  });
  
  app.listen(3000);
}
```

---

## 6. Managing Secrets per Environment

### Separating Development, Staging, and Production

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

## 7. Managing Secrets in CI/CD

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
          # Run the deploy script
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

## 8. Secret Rotation

### Automatic Rotation Strategy

```javascript
// Secret rotation scheduler
const cron = require('node-cron');

// Rotate API keys at 2 AM on the 1st of every month
cron.schedule('0 2 1 * *', async () => {
  console.log('🔄 Starting API key rotation...');
  
  try {
    // 1. Generate a new API key
    const newApiKey = await generateNewApiKey();
    
    // 2. Store it in Secrets Manager
    await secretsManager.updateSecret({
      SecretId: 'myapp/api-keys',
      SecretString: JSON.stringify({
        current: newApiKey,
        previous: oldApiKey  // Keep the previous key for one cycle
      })
    }).promise();
    
    // 3. Send the new key to partners (automatically or manually)
    await notifyPartners(newApiKey);
    
    // 4. Fully delete the old key after 30 days
    scheduleKeyDeletion(oldApiKey, 30);
    
    console.log('✅ API key rotation complete');
  } catch (err) {
    console.error('❌ API key rotation failed:', err);
    // Send an alert
    await sendAlert('API key rotation failed', err);
  }
});
```

---

## Best Practices Summary

### Storage
- ✅ Never hardcode secrets in code
- ✅ Add .env files to .gitignore
- ✅ Use a secrets manager in production
- ✅ Use different secrets per environment
- ✅ Store secrets encrypted

### Access
- ✅ Apply the principle of least privilege
- ✅ Log secret access
- ✅ Use temporary credentials (where possible)
- ✅ Cache secrets for better performance
- ✅ Set expiration times

### Management
- ✅ Rotate secrets regularly
- ✅ Delete unused secrets
- ✅ Track secret change history
- ✅ Provide a .env.example
- ✅ Train and document for the team

### Monitoring
- ✅ Detect anomalous secret access
- ✅ Alert on secret expiration
- ✅ Detect secrets pushed to GitHub
- ✅ Alert on failed secret rotation

---

## Conclusion

Secrets management is a security fundamental. Start with environment variables during development, but in production always use a dedicated tool such as AWS Secrets Manager, HashiCorp Vault, or Azure Key Vault.

**Recommended strategy:**
- **Local development**: .env files
- **Staging/production**: Secrets Manager
- **Enterprise**: HashiCorp Vault
- **Multi-cloud**: Vault or each cloud's own secrets service

Once a secret leaks, you can't take it back. Prevention is the best cure!
