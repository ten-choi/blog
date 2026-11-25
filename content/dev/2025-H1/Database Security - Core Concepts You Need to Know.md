---
title: "Database Security - Core Concepts You Need to Know"
labels: ["security","database","backend","sql","Archive"]
published: true
date: 2025-01-25T17:24:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "471423326355121812"
source: "archive"
archivePath: "_archive/dev/security/database-security-guide-kr.md"
---

# Database Security - Core Concepts You Need to Know

Databases hold your most important asset: your data. Database security is key to preventing data breaches, unauthorized access, and data loss.

---

## 1. Encryption at Rest ⭐️⭐️⭐️

### Concept
Encrypt data stored on disk so it stays protected even if someone gains physical access.

### PostgreSQL Encryption

**1. TDE (Transparent Data Encryption)**
```sql
-- Install the pgcrypto extension
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Encrypt sensitive columns
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    -- Encrypted credit card number
    credit_card BYTEA,
    -- Encrypted national ID number
    ssn BYTEA
);

-- Insert data (encrypted)
INSERT INTO users (username, email, credit_card, ssn)
VALUES (
    'john_doe',
    'john@example.com',
    pgp_sym_encrypt('1234-5678-9012-3456', 'encryption_key'),
    pgp_sym_encrypt('123456-1234567', 'encryption_key')
);

-- Query data (decrypted)
SELECT 
    username,
    email,
    pgp_sym_decrypt(credit_card, 'encryption_key') AS credit_card,
    pgp_sym_decrypt(ssn, 'encryption_key') AS ssn
FROM users
WHERE id = 1;
```

**2. Column-Level Encryption (application level)**
```javascript
const crypto = require('crypto');

class DatabaseEncryption {
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
    
    // Combine IV + auth tag + ciphertext
    return Buffer.concat([
      iv,
      authTag,
      Buffer.from(encrypted, 'hex')
    ]).toString('base64');
  }
  
  decrypt(encryptedData) {
    const buffer = Buffer.from(encryptedData, 'base64');
    
    const iv = buffer.slice(0, 16);
    const authTag = buffer.slice(16, 32);
    const encrypted = buffer.slice(32);
    
    const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encrypted, null, 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }
}

// Usage
const encryptor = new DatabaseEncryption(process.env.DB_ENCRYPTION_KEY);

// Store data
const encryptedSSN = encryptor.encrypt('123456-1234567');
await db.query(
  'INSERT INTO users (username, ssn) VALUES ($1, $2)',
  ['john_doe', encryptedSSN]
);

// Read data
const { rows } = await db.query('SELECT ssn FROM users WHERE id = $1', [userId]);
const decryptedSSN = encryptor.decrypt(rows[0].ssn);
```

### MySQL/MariaDB Encryption

```sql
-- Encrypt an InnoDB table
CREATE TABLE sensitive_data (
    id INT PRIMARY KEY AUTO_INCREMENT,
    data VARCHAR(255)
) ENCRYPTION='Y';

-- Encrypt an existing table
ALTER TABLE users ENCRYPTION='Y';

-- AES encrypt/decrypt functions
INSERT INTO users (email, password)
VALUES (
    'user@example.com',
    AES_ENCRYPT('mypassword', UNHEX(SHA2('encryption_key', 512)))
);

SELECT 
    email,
    CAST(AES_DECRYPT(password, UNHEX(SHA2('encryption_key', 512))) AS CHAR) AS password
FROM users;
```

### MongoDB Encryption

```javascript
// MongoDB Client-Side Field Level Encryption
const { MongoClient, ClientEncryption } = require('mongodb');

const client = new MongoClient(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  autoEncryption: {
    keyVaultNamespace: 'encryption.__keyVault',
    kmsProviders: {
      aws: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
      }
    },
    schemaMap: {
      'mydb.users': {
        bsonType: 'object',
        properties: {
          ssn: {
            encrypt: {
              keyId: [dataKeyId],
              bsonType: 'string',
              algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Deterministic'
            }
          },
          creditCard: {
            encrypt: {
              keyId: [dataKeyId],
              bsonType: 'string',
              algorithm: 'AEAD_AES_256_CBC_HMAC_SHA_512-Random'
            }
          }
        }
      }
    }
  }
});

// Insert data (encrypted automatically)
await db.collection('users').insertOne({
  username: 'john_doe',
  ssn: '123-45-6789', // encrypted automatically
  creditCard: '1234-5678-9012-3456'
});
```

---

## 2. Database Access Control ⭐️⭐️⭐️

### Concept
Control access to the database so unauthorized users can't get in.

### PostgreSQL Users and Privileges

```sql
-- 1. Create a read-only user
CREATE USER readonly_user WITH PASSWORD 'secure_password';

-- Read access to tables in a specific schema only
GRANT CONNECT ON DATABASE mydb TO readonly_user;
GRANT USAGE ON SCHEMA public TO readonly_user;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public 
    GRANT SELECT ON TABLES TO readonly_user;

-- 2. Application user (CRUD privileges)
CREATE USER app_user WITH PASSWORD 'app_password';
GRANT CONNECT ON DATABASE mydb TO app_user;
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;

-- 3. Admin user
CREATE USER admin_user WITH PASSWORD 'admin_password';
GRANT ALL PRIVILEGES ON DATABASE mydb TO admin_user;

-- 4. Row-Level Security (RLS)
-- So users can only see their own data
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

CREATE POLICY user_documents ON documents
    FOR ALL
    TO app_user
    USING (user_id = current_user_id());

-- 5. Allow access only from specific IPs
-- pg_hba.conf
# TYPE  DATABASE  USER          ADDRESS          METHOD
host    mydb      app_user      10.0.0.0/8       md5
host    mydb      admin_user    192.168.1.100/32 md5
```

### MySQL Users and Privileges

```sql
-- 1. Create users and grant privileges
CREATE USER 'readonly_user'@'10.0.%' IDENTIFIED BY 'secure_password';
GRANT SELECT ON mydb.* TO 'readonly_user'@'10.0.%';

CREATE USER 'app_user'@'10.0.%' IDENTIFIED BY 'app_password';
GRANT SELECT, INSERT, UPDATE, DELETE ON mydb.* TO 'app_user'@'10.0.%';

-- 2. Check privileges
SHOW GRANTS FOR 'app_user'@'10.0.%';

-- 3. Revoke privileges
REVOKE DELETE ON mydb.* FROM 'app_user'@'10.0.%';

-- 4. Privileges on specific tables only
GRANT SELECT ON mydb.users TO 'limited_user'@'%';
GRANT SELECT (id, username, email) ON mydb.users TO 'limited_user'@'%';

-- 5. Require SSL connections
ALTER USER 'secure_user'@'%' REQUIRE SSL;

FLUSH PRIVILEGES;
```

### MongoDB Access Control

```javascript
// 1. Enable authentication
// mongod.conf
security:
  authorization: enabled

// 2. Create users
use admin
db.createUser({
  user: "admin",
  pwd: "adminPassword",
  roles: [ { role: "userAdminAnyDatabase", db: "admin" } ]
})

use mydb
db.createUser({
  user: "app_user",
  pwd: "appPassword",
  roles: [
    { role: "readWrite", db: "mydb" }
  ]
})

// 3. Read-only user
db.createUser({
  user: "readonly_user",
  pwd: "readonlyPassword",
  roles: [
    { role: "read", db: "mydb" }
  ]
})

// 4. Create a custom role
db.createRole({
  role: "customRole",
  privileges: [
    {
      resource: { db: "mydb", collection: "users" },
      actions: [ "find", "insert", "update" ]
    }
  ],
  roles: []
})
```

---

## 3. Backup Security ⭐️⭐️⭐️

### Concept
Backups protect against data loss, but the backups themselves need to be secured too.

### Secure PostgreSQL Backups

```bash
#!/bin/bash
# secure-backup.sh

# Environment variables
DB_NAME="mydb"
DB_USER="backup_user"
BACKUP_DIR="/backups"
ENCRYPTION_KEY="/secure/backup.key"
S3_BUCKET="s3://my-secure-backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/${DB_NAME}_${DATE}.sql"

# 1. Dump the database
PGPASSWORD=${DB_PASSWORD} pg_dump \
    -h localhost \
    -U ${DB_USER} \
    -F c \
    -b \
    -v \
    -f ${BACKUP_FILE} \
    ${DB_NAME}

# 2. Encrypt
gpg --symmetric \
    --cipher-algo AES256 \
    --passphrase-file ${ENCRYPTION_KEY} \
    ${BACKUP_FILE}

# 3. Compress
gzip ${BACKUP_FILE}.gpg

# 4. Upload to S3 (server-side encryption)
aws s3 cp ${BACKUP_FILE}.gpg.gz ${S3_BUCKET}/ \
    --server-side-encryption AES256 \
    --storage-class GLACIER

# 5. Delete local files
shred -vfz -n 10 ${BACKUP_FILE}
rm -f ${BACKUP_FILE}.gpg.gz

# 6. Delete old backups (older than 30 days)
aws s3 ls ${S3_BUCKET}/ | while read -r line; do
    createDate=$(echo $line | awk '{print $1" "$2}')
    createDate=$(date -d "$createDate" +%s)
    olderThan=$(date -d "30 days ago" +%s)
    
    if [[ $createDate -lt $olderThan ]]; then
        fileName=$(echo $line | awk '{print $4}')
        aws s3 rm ${S3_BUCKET}/${fileName}
    fi
done
```

### Restoring a Backup

```bash
#!/bin/bash
# restore-backup.sh

BACKUP_FILE="mydb_20240101_120000.sql.gpg.gz"
S3_BUCKET="s3://my-secure-backups"
ENCRYPTION_KEY="/secure/backup.key"
DB_NAME="mydb"

# 1. Download from S3
aws s3 cp ${S3_BUCKET}/${BACKUP_FILE} .

# 2. Decompress
gunzip ${BACKUP_FILE}

# 3. Decrypt
gpg --decrypt \
    --passphrase-file ${ENCRYPTION_KEY} \
    ${BACKUP_FILE%.gz} > mydb_restore.sql

# 4. Restore
psql -U postgres -d ${DB_NAME} < mydb_restore.sql

# 5. Securely delete the files
shred -vfz -n 10 mydb_restore.sql ${BACKUP_FILE%.gz}
```

### Automated Backup with Cron

```bash
# crontab -e
# Back up every day at 2 AM
0 2 * * * /usr/local/bin/secure-backup.sh >> /var/log/backup.log 2>&1

# Full backup every Sunday at 3 AM
0 3 * * 0 /usr/local/bin/full-backup.sh >> /var/log/backup.log 2>&1
```

---

## 4. Audit Logging ⭐️⭐️

### Concept
Log every operation on the database so everything is traceable.

### PostgreSQL Audit Logging

```sql
-- Install the pgAudit extension
CREATE EXTENSION pgaudit;

-- Configuration (postgresql.conf)
pgaudit.log = 'read, write, ddl'
pgaudit.log_catalog = on
pgaudit.log_parameter = on
pgaudit.log_relation = on

-- Auditing specific tables
CREATE TABLE audit_log (
    id SERIAL PRIMARY KEY,
    table_name TEXT,
    action TEXT,
    old_data JSONB,
    new_data JSONB,
    user_name TEXT DEFAULT current_user,
    action_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Trigger function
CREATE OR REPLACE FUNCTION audit_trigger_func()
RETURNS TRIGGER AS $$
BEGIN
    IF (TG_OP = 'DELETE') THEN
        INSERT INTO audit_log (table_name, action, old_data)
        VALUES (TG_TABLE_NAME, TG_OP, row_to_json(OLD));
        RETURN OLD;
    ELSIF (TG_OP = 'UPDATE') THEN
        INSERT INTO audit_log (table_name, action, old_data, new_data)
        VALUES (TG_TABLE_NAME, TG_OP, row_to_json(OLD), row_to_json(NEW));
        RETURN NEW;
    ELSIF (TG_OP = 'INSERT') THEN
        INSERT INTO audit_log (table_name, action, new_data)
        VALUES (TG_TABLE_NAME, TG_OP, row_to_json(NEW));
        RETURN NEW;
    END IF;
END;
$$ LANGUAGE plpgsql;

-- Attach the trigger
CREATE TRIGGER users_audit_trigger
AFTER INSERT OR UPDATE OR DELETE ON users
FOR EACH ROW EXECUTE FUNCTION audit_trigger_func();
```

### MySQL Audit Plugin

```sql
-- Install the audit plugin
INSTALL PLUGIN audit_log SONAME 'audit_log.so';

-- Configuration (my.cnf)
[mysqld]
audit_log_policy=ALL
audit_log_format=JSON
audit_log_file=/var/log/mysql/audit.log

-- Audit specific users
SET GLOBAL audit_log_include_accounts = 'app_user@%,admin@%';

-- Log only specific events
SET GLOBAL audit_log_policy = 'LOGINS';
```

### Application-Level Auditing

```javascript
// Audit logging with Sequelize hooks
const { Model, DataTypes } = require('sequelize');

class AuditLog extends Model {}
AuditLog.init({
  tableName: DataTypes.STRING,
  action: DataTypes.STRING,
  oldData: DataTypes.JSONB,
  newData: DataTypes.JSONB,
  userId: DataTypes.INTEGER,
  ipAddress: DataTypes.STRING,
  userAgent: DataTypes.STRING
}, { sequelize });

// Add hooks to the User model
User.addHook('afterCreate', async (user, options) => {
  await AuditLog.create({
    tableName: 'users',
    action: 'INSERT',
    newData: user.toJSON(),
    userId: options.userId,
    ipAddress: options.ipAddress,
    userAgent: options.userAgent
  });
});

User.addHook('afterUpdate', async (user, options) => {
  await AuditLog.create({
    tableName: 'users',
    action: 'UPDATE',
    oldData: user._previousDataValues,
    newData: user.toJSON(),
    userId: options.userId,
    ipAddress: options.ipAddress
  });
});

User.addHook('afterDestroy', async (user, options) => {
  await AuditLog.create({
    tableName: 'users',
    action: 'DELETE',
    oldData: user.toJSON(),
    userId: options.userId,
    ipAddress: options.ipAddress
  });
});

// Usage
await User.update(
  { email: 'newemail@example.com' },
  { 
    where: { id: 1 },
    userId: req.user.id,
    ipAddress: req.ip,
    userAgent: req.get('user-agent')
  }
);
```

---

## 5. Connection Security ⭐️⭐️

### Concept
Encrypt database connections to prevent man-in-the-middle attacks.

### SSL/TLS Connections

**PostgreSQL**
```javascript
// Node.js - pg library
const { Pool } = require('pg');

const pool = new Pool({
  host: 'database.example.com',
  port: 5432,
  database: 'mydb',
  user: 'app_user',
  password: process.env.DB_PASSWORD,
  
  // SSL settings
  ssl: {
    rejectUnauthorized: true,
    ca: fs.readFileSync('/path/to/ca-certificate.crt').toString(),
    key: fs.readFileSync('/path/to/client-key.key').toString(),
    cert: fs.readFileSync('/path/to/client-cert.crt').toString()
  },
  
  // Connection pool settings
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000
});
```

**MySQL**
```javascript
// Node.js - mysql2 library
const mysql = require('mysql2');

const pool = mysql.createPool({
  host: 'database.example.com',
  port: 3306,
  database: 'mydb',
  user: 'app_user',
  password: process.env.DB_PASSWORD,
  
  // SSL settings
  ssl: {
    ca: fs.readFileSync('/path/to/ca.pem'),
    key: fs.readFileSync('/path/to/client-key.pem'),
    cert: fs.readFileSync('/path/to/client-cert.pem')
  },
  
  // Connection pool settings
  connectionLimit: 10,
  queueLimit: 0
});
```

**MongoDB**
```javascript
// Node.js - mongodb library
const { MongoClient } = require('mongodb');

const client = new MongoClient(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  
  // TLS settings
  tls: true,
  tlsCAFile: '/path/to/ca.pem',
  tlsCertificateKeyFile: '/path/to/client.pem',
  
  // Authentication
  authSource: 'admin',
  authMechanism: 'SCRAM-SHA-256'
});
```

---

## 6. Extra SQL Injection Defenses ⭐️⭐️⭐️

### Defenses Beyond Prepared Statements

**1. Query Parameterization (always use it)**
```javascript
// ❌ Dangerous
const query = `SELECT * FROM users WHERE id = ${req.params.id}`;

// ✅ Safe
const query = 'SELECT * FROM users WHERE id = $1';
const result = await pool.query(query, [req.params.id]);

// ✅ Named parameters (clearer)
const query = 'SELECT * FROM users WHERE username = :username AND email = :email';
const result = await pool.query(query, {
  username: req.body.username,
  email: req.body.email
});
```

**2. Use an ORM/Query Builder**
```javascript
// Sequelize
const user = await User.findOne({
  where: {
    username: req.body.username,
    email: req.body.email
  }
});

// Knex.js
const users = await knex('users')
  .where('username', req.body.username)
  .where('email', req.body.email)
  .select('*');

// Prisma
const user = await prisma.user.findFirst({
  where: {
    AND: [
      { username: req.body.username },
      { email: req.body.email }
    ]
  }
});
```

**3. Input Validation**
```javascript
const Joi = require('joi');

const schema = Joi.object({
  id: Joi.number().integer().positive().required(),
  username: Joi.string().alphanum().min(3).max(30).required(),
  email: Joi.string().email().required()
});

app.get('/api/user/:id', async (req, res) => {
  const { error } = schema.validate(req.params);
  if (error) {
    return res.status(400).json({ error: error.details[0].message });
  }
  
  // Run the query safely
  const user = await pool.query(
    'SELECT * FROM users WHERE id = $1',
    [req.params.id]
  );
  
  res.json(user.rows[0]);
});
```

---

## Conclusion

Database security checklist:

### Essential Measures (⭐️⭐️⭐️)
- ✅ Encryption at rest (sensitive columns)
- ✅ Strong access control (least privilege)
- ✅ SSL/TLS connections
- ✅ Prepared statements

### Important Measures (⭐️⭐️)
- ✅ Encrypted backups
- ✅ Audit logging
- ✅ Row-level security
- ✅ Connection pooling configuration

### Extra Hardening (⭐️)
- ✅ Regular backup testing
- ✅ Remote backup storage (S3, Glacier)
- ✅ Database firewall
- ✅ Regular security patches

**Your database is your most important asset. Protect it with defense in depth!**
