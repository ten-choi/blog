---
title: 데이터베이스 보안 - 알아야 할 핵심 개념
published: false
description: 데이터베이스 보안의 핵심 개념들을 쉽게 설명합니다. 암호화, 접근 제어, 백업 보안, 감사 로깅 등에 대해 알아봅니다.
tags: security, database, backend, sql
cover_image: https://example.com/your-cover-image.jpg
---

# 데이터베이스 보안 - 알아야 할 핵심 개념

데이터베이스는 가장 중요한 자산인 데이터를 저장합니다. 데이터베이스 보안은 데이터 유출, 무단 접근, 데이터 손실을 방지하는 핵심 요소입니다.

---

## 1. Encryption at Rest (저장 데이터 암호화) ⭐️⭐️⭐️

### 개념
디스크에 저장된 데이터를 암호화하여, 물리적 접근 시에도 데이터를 보호합니다.

### PostgreSQL 암호화

**1. TDE (Transparent Data Encryption)**
```sql
-- pgcrypto 확장 설치
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 민감한 열 암호화
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    -- 신용카드 번호 암호화
    credit_card BYTEA,
    -- 주민등록번호 암호화
    ssn BYTEA
);

-- 데이터 삽입 (암호화)
INSERT INTO users (username, email, credit_card, ssn)
VALUES (
    'john_doe',
    'john@example.com',
    pgp_sym_encrypt('1234-5678-9012-3456', 'encryption_key'),
    pgp_sym_encrypt('123456-1234567', 'encryption_key')
);

-- 데이터 조회 (복호화)
SELECT 
    username,
    email,
    pgp_sym_decrypt(credit_card, 'encryption_key') AS credit_card,
    pgp_sym_decrypt(ssn, 'encryption_key') AS ssn
FROM users
WHERE id = 1;
```

**2. Column-Level Encryption (애플리케이션 레벨)**
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
    
    // IV + AuthTag + 암호문 결합
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

// 사용 예
const encryptor = new DatabaseEncryption(process.env.DB_ENCRYPTION_KEY);

// 데이터 저장
const encryptedSSN = encryptor.encrypt('123456-1234567');
await db.query(
  'INSERT INTO users (username, ssn) VALUES ($1, $2)',
  ['john_doe', encryptedSSN]
);

// 데이터 조회
const { rows } = await db.query('SELECT ssn FROM users WHERE id = $1', [userId]);
const decryptedSSN = encryptor.decrypt(rows[0].ssn);
```

### MySQL/MariaDB 암호화

```sql
-- InnoDB 테이블 암호화
CREATE TABLE sensitive_data (
    id INT PRIMARY KEY AUTO_INCREMENT,
    data VARCHAR(255)
) ENCRYPTION='Y';

-- 기존 테이블 암호화
ALTER TABLE users ENCRYPTION='Y';

-- AES 암호화/복호화 함수
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

### MongoDB 암호화

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

// 데이터 삽입 (자동 암호화)
await db.collection('users').insertOne({
  username: 'john_doe',
  ssn: '123-45-6789', // 자동으로 암호화됨
  creditCard: '1234-5678-9012-3456'
});
```

---

## 2. Database Access Control ⭐️⭐️⭐️

### 개념
데이터베이스 접근을 제어하여 권한 없는 사용자의 접근을 방지합니다.

### PostgreSQL 사용자 및 권한 관리

```sql
-- 1. 읽기 전용 사용자 생성
CREATE USER readonly_user WITH PASSWORD 'secure_password';

-- 특정 스키마의 테이블 읽기 권한만
GRANT CONNECT ON DATABASE mydb TO readonly_user;
GRANT USAGE ON SCHEMA public TO readonly_user;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public 
    GRANT SELECT ON TABLES TO readonly_user;

-- 2. 애플리케이션 사용자 (CRUD 권한)
CREATE USER app_user WITH PASSWORD 'app_password';
GRANT CONNECT ON DATABASE mydb TO app_user;
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;

-- 3. 관리자 사용자
CREATE USER admin_user WITH PASSWORD 'admin_password';
GRANT ALL PRIVILEGES ON DATABASE mydb TO admin_user;

-- 4. Row-Level Security (RLS)
-- 사용자가 자신의 데이터만 볼 수 있도록
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

CREATE POLICY user_documents ON documents
    FOR ALL
    TO app_user
    USING (user_id = current_user_id());

-- 5. 특정 IP에서만 접근 허용
-- pg_hba.conf
# TYPE  DATABASE  USER          ADDRESS          METHOD
host    mydb      app_user      10.0.0.0/8       md5
host    mydb      admin_user    192.168.1.100/32 md5
```

### MySQL 사용자 및 권한 관리

```sql
-- 1. 사용자 생성 및 권한 부여
CREATE USER 'readonly_user'@'10.0.%' IDENTIFIED BY 'secure_password';
GRANT SELECT ON mydb.* TO 'readonly_user'@'10.0.%';

CREATE USER 'app_user'@'10.0.%' IDENTIFIED BY 'app_password';
GRANT SELECT, INSERT, UPDATE, DELETE ON mydb.* TO 'app_user'@'10.0.%';

-- 2. 권한 확인
SHOW GRANTS FOR 'app_user'@'10.0.%';

-- 3. 권한 취소
REVOKE DELETE ON mydb.* FROM 'app_user'@'10.0.%';

-- 4. 특정 테이블에만 권한
GRANT SELECT ON mydb.users TO 'limited_user'@'%';
GRANT SELECT (id, username, email) ON mydb.users TO 'limited_user'@'%';

-- 5. SSL 연결 강제
ALTER USER 'secure_user'@'%' REQUIRE SSL;

FLUSH PRIVILEGES;
```

### MongoDB 접근 제어

```javascript
// 1. 인증 활성화
// mongod.conf
security:
  authorization: enabled

// 2. 사용자 생성
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

// 3. 읽기 전용 사용자
db.createUser({
  user: "readonly_user",
  pwd: "readonlyPassword",
  roles: [
    { role: "read", db: "mydb" }
  ]
})

// 4. 커스텀 롤 생성
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

### 개념
백업은 데이터 손실을 방지하지만, 백업 자체도 보안이 필요합니다.

### 안전한 PostgreSQL 백업

```bash
#!/bin/bash
# secure-backup.sh

# 환경 변수
DB_NAME="mydb"
DB_USER="backup_user"
BACKUP_DIR="/backups"
ENCRYPTION_KEY="/secure/backup.key"
S3_BUCKET="s3://my-secure-backups"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/${DB_NAME}_${DATE}.sql"

# 1. 데이터베이스 덤프
PGPASSWORD=${DB_PASSWORD} pg_dump \
    -h localhost \
    -U ${DB_USER} \
    -F c \
    -b \
    -v \
    -f ${BACKUP_FILE} \
    ${DB_NAME}

# 2. 암호화
gpg --symmetric \
    --cipher-algo AES256 \
    --passphrase-file ${ENCRYPTION_KEY} \
    ${BACKUP_FILE}

# 3. 압축
gzip ${BACKUP_FILE}.gpg

# 4. S3에 업로드 (서버 사이드 암호화)
aws s3 cp ${BACKUP_FILE}.gpg.gz ${S3_BUCKET}/ \
    --server-side-encryption AES256 \
    --storage-class GLACIER

# 5. 로컬 파일 삭제
shred -vfz -n 10 ${BACKUP_FILE}
rm -f ${BACKUP_FILE}.gpg.gz

# 6. 오래된 백업 삭제 (30일 이상)
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

### 백업 복원

```bash
#!/bin/bash
# restore-backup.sh

BACKUP_FILE="mydb_20240101_120000.sql.gpg.gz"
S3_BUCKET="s3://my-secure-backups"
ENCRYPTION_KEY="/secure/backup.key"
DB_NAME="mydb"

# 1. S3에서 다운로드
aws s3 cp ${S3_BUCKET}/${BACKUP_FILE} .

# 2. 압축 해제
gunzip ${BACKUP_FILE}

# 3. 복호화
gpg --decrypt \
    --passphrase-file ${ENCRYPTION_KEY} \
    ${BACKUP_FILE%.gz} > mydb_restore.sql

# 4. 복원
psql -U postgres -d ${DB_NAME} < mydb_restore.sql

# 5. 파일 안전 삭제
shred -vfz -n 10 mydb_restore.sql ${BACKUP_FILE%.gz}
```

### Automated Backup with Cron

```bash
# crontab -e
# 매일 새벽 2시에 백업
0 2 * * * /usr/local/bin/secure-backup.sh >> /var/log/backup.log 2>&1

# 매주 일요일 새벽 3시에 전체 백업
0 3 * * 0 /usr/local/bin/full-backup.sh >> /var/log/backup.log 2>&1
```

---

## 4. Audit Logging (감사 로깅) ⭐️⭐️

### 개념
데이터베이스의 모든 작업을 로깅하여 추적 가능하게 합니다.

### PostgreSQL Audit Logging

```sql
-- pgAudit 확장 설치
CREATE EXTENSION pgaudit;

-- 설정 (postgresql.conf)
pgaudit.log = 'read, write, ddl'
pgaudit.log_catalog = on
pgaudit.log_parameter = on
pgaudit.log_relation = on

-- 특정 테이블 감사
CREATE TABLE audit_log (
    id SERIAL PRIMARY KEY,
    table_name TEXT,
    action TEXT,
    old_data JSONB,
    new_data JSONB,
    user_name TEXT DEFAULT current_user,
    action_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 트리거 함수
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

-- 트리거 적용
CREATE TRIGGER users_audit_trigger
AFTER INSERT OR UPDATE OR DELETE ON users
FOR EACH ROW EXECUTE FUNCTION audit_trigger_func();
```

### MySQL Audit Plugin

```sql
-- Audit Plugin 설치
INSTALL PLUGIN audit_log SONAME 'audit_log.so';

-- 설정 (my.cnf)
[mysqld]
audit_log_policy=ALL
audit_log_format=JSON
audit_log_file=/var/log/mysql/audit.log

-- 특정 사용자 감사
SET GLOBAL audit_log_include_accounts = 'app_user@%,admin@%';

-- 특정 이벤트만 로깅
SET GLOBAL audit_log_policy = 'LOGINS';
```

### 애플리케이션 레벨 감사

```javascript
// Sequelize Hooks를 이용한 감사 로깅
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

// User 모델에 훅 추가
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

// 사용 예
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

### 개념
데이터베이스 연결을 암호화하여 중간자 공격을 방지합니다.

### SSL/TLS 연결

**PostgreSQL**
```javascript
// Node.js - pg 라이브러리
const { Pool } = require('pg');

const pool = new Pool({
  host: 'database.example.com',
  port: 5432,
  database: 'mydb',
  user: 'app_user',
  password: process.env.DB_PASSWORD,
  
  // SSL 설정
  ssl: {
    rejectUnauthorized: true,
    ca: fs.readFileSync('/path/to/ca-certificate.crt').toString(),
    key: fs.readFileSync('/path/to/client-key.key').toString(),
    cert: fs.readFileSync('/path/to/client-cert.crt').toString()
  },
  
  // Connection Pool 설정
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000
});
```

**MySQL**
```javascript
// Node.js - mysql2 라이브러리
const mysql = require('mysql2');

const pool = mysql.createPool({
  host: 'database.example.com',
  port: 3306,
  database: 'mydb',
  user: 'app_user',
  password: process.env.DB_PASSWORD,
  
  // SSL 설정
  ssl: {
    ca: fs.readFileSync('/path/to/ca.pem'),
    key: fs.readFileSync('/path/to/client-key.pem'),
    cert: fs.readFileSync('/path/to/client-cert.pem')
  },
  
  // Connection Pool 설정
  connectionLimit: 10,
  queueLimit: 0
});
```

**MongoDB**
```javascript
// Node.js - mongodb 라이브러리
const { MongoClient } = require('mongodb');

const client = new MongoClient(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  
  // TLS 설정
  tls: true,
  tlsCAFile: '/path/to/ca.pem',
  tlsCertificateKeyFile: '/path/to/client.pem',
  
  // 인증
  authSource: 'admin',
  authMechanism: 'SCRAM-SHA-256'
});
```

---

## 6. SQL Injection 추가 방어 ⭐️⭐️⭐️

### Prepared Statements 외 추가 방어

**1. Query Parameterization (항상 사용)**
```javascript
// ❌ 위험한 방법
const query = `SELECT * FROM users WHERE id = ${req.params.id}`;

// ✅ 안전한 방법
const query = 'SELECT * FROM users WHERE id = $1';
const result = await pool.query(query, [req.params.id]);

// ✅ Named Parameters (더 명확)
const query = 'SELECT * FROM users WHERE username = :username AND email = :email';
const result = await pool.query(query, {
  username: req.body.username,
  email: req.body.email
});
```

**2. ORM/Query Builder 사용**
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
  
  // 안전하게 쿼리 실행
  const user = await pool.query(
    'SELECT * FROM users WHERE id = $1',
    [req.params.id]
  );
  
  res.json(user.rows[0]);
});
```

---

## 결론

데이터베이스 보안 체크리스트:

### 필수 보안 조치 (⭐️⭐️⭐️)
- ✅ 저장 데이터 암호화 (민감한 열)
- ✅ 강력한 접근 제어 (최소 권한)
- ✅ SSL/TLS 연결
- ✅ Prepared Statements 사용

### 중요 보안 조치 (⭐️⭐️)
- ✅ 암호화된 백업
- ✅ 감사 로깅
- ✅ Row-Level Security
- ✅ Connection Pooling 설정

### 추가 보안 강화 (⭐️)
- ✅ 정기적인 백업 테스트
- ✅ 백업 원격 저장 (S3, Glacier)
- ✅ 데이터베이스 방화벽
- ✅ 정기적인 보안 패치

**데이터베이스는 가장 중요한 자산입니다. 다층 보안(Defense in Depth)으로 보호하세요!**
