---
title: MySQL Performance Optimization
published: false
description: Testing a post in a category subfolder
tags: database, rdb, mysql, optimization
cover_image: https://example.com/your-cover-image.jpg
series: Testing Series
---

# Complete Guide to MySQL Performance Optimization

MySQL is one of the most popular relational databases, but it can experience performance issues in large-scale applications or high-traffic environments. This document provides strategies and techniques for optimizing MySQL database performance.

## Table of Contents

1. [Scalability](#1-scalability)
2. [Performance Optimization](#2-performance-optimization)
3. [Data Consistency & High Availability](#3-data-consistency--high-availability)
4. [Query Optimization](#4-query-optimization)
5. [Hardware & System Configuration](#5-hardware--system-configuration)
6. [Partitioning](#6-partitioning)
7. [Advanced Optimization Techniques](#7-advanced-optimization-techniques)
8. [Case Studies](#8-case-studies)
9. [New Features in MySQL 8.0+](#9-new-features-in-mysql-80)
10. [Key Performance Monitoring Metrics](#10-key-performance-monitoring-metrics)

## 1. Scalability

### Vertical Scaling

Upgrade to a server with more powerful CPU, memory, and storage
Pros: Easy to implement
Cons: Limited scalability and exponentially increasing costs

### Read Replica Configuration

**Steps to distribute read traffic across multiple replicas**:

1. Prepare two servers

2. Modify or add the following values in /etc/mysql/my.cnf:

```
server-id = 1        # Must be unique across servers
log_bin = mysql-bin  # Required log for replication
binlog_format = ROW  # ROW format is generally recommended
```

3. Create a user and grant privileges required for replication,
   then apply the privileges:

```ddl
CREATE USER 'replication_user'@'%' IDENTIFIED BY 'password';
GRANT REPLICATION SLAVE ON *.* TO 'replication_user'@'%';
FLUSH PRIVILEGES;
```

4. Check the current status of the master:

```sql
SHOW MASTER STATUS;
```

5. If there are no issues, dump the existing master data and import it to the replica:

```ddl
mysqldump -u root -p --all-databases --master-data=2 --single-transaction > dump.sql
mysql -u root -p < dump.sql
```

6. Set the server-id on the replica to be different from the master.

7. Configure the slave's database to connect to the master and start the slave:

```ddl
CHANGE MASTER TO
  MASTER_HOST='master_host_ip',         -- Set IP or domain of the Master server
  MASTER_USER='replication_user',       -- Replication-specific user created on the Master
  MASTER_PASSWORD='password',           -- Password for the replication user
  MASTER_LOG_FILE='mysql-bin.000001',   -- Current Binlog filename from SHOW MASTER STATUS
  MASTER_LOG_POS=107;                   -- Replication start position in Binlog (byte offset) from SHOW MASTER STATUS

START SLAVE;  -- or START REPLICA; (depending on MySQL version)
```

### ProxySQL for Read/Write Separation

ProxySQL can be implemented on a separate server from the master and slave to handle read/write separation and load balancing:

```bash
# ProxySQL configuration example
UPDATE mysql_servers SET weight=10 WHERE hostname='reader1';
UPDATE mysql_servers SET weight=5 WHERE hostname='reader2';
LOAD MYSQL SERVERS TO RUNTIME;
```

Although this approach requires more resources, it can be used for the following reasons:

**Benefits of using ProxySQL**:

1. **Simplified application architecture**:
   Applications can be unaware of read/write separation or replica server management,
   as business logic only needs to connect to ProxySQL.

2. **Advanced load balancing capabilities**:
   Efficiently distributes load when working with 3+ replicas using weight-based algorithms.
   Example: 50% of traffic to one replica, 30% to another, and 20% to a third.

3. **Real-time traffic management**:
   Operations teams can add/remove servers or adjust weights without application modifications,
   by changing only ProxySQL settings.

4. **Enhanced failure handling and high availability**:
   When combined with Orchestrator, ProxySQL enables automatic failure detection and failover.

### Sharding

MySQL doesn't natively support sharding, so filtering must be implemented at the application or middleware level based on specific values.
Systems without built-in sharding support may need to carefully evaluate if the complexity of implementing sharding outweighs the benefits.

**Sharding approaches**:

- **Data distribution**: Spread data across multiple servers (horizontal partitioning)
- **Implementation methods**:
  - Range-Based Sharding
  - Hash-Based Sharding
  - Directory-Based Sharding

**Example implementation**:

```sql
-- Example table for Shard 1 (User IDs 1-1000000)
CREATE TABLE users_shard1 (
  id INT PRIMARY KEY,
  name VARCHAR(100),
  /* Other fields */
  CONSTRAINT check_id CHECK (id BETWEEN 1 AND 1000000)
);

-- Example table for Shard 2 (User IDs 1000001-2000000)
CREATE TABLE users_shard2 (
  id INT PRIMARY KEY,
  name VARCHAR(100),
  /* Other fields */
  CONSTRAINT check_id CHECK (id BETWEEN 1000001 AND 2000000)
);
```

## 2. Performance Optimization

**Problem**: Query performance degradation when processing large amounts of data or high traffic.

**Solutions**:

### Index Optimization

**Best practices for indexing**:

- **Design appropriate indexes**: Create indexes for columns frequently used in WHERE, JOIN, and ORDER BY clauses

  ```sql
  -- Create a basic index
  CREATE INDEX idx_last_name ON users(last_name);

  -- Create a composite index
  CREATE INDEX idx_last_first_name ON users(last_name, first_name);

  -- Check index status
  SHOW INDEX FROM users;
  ```

- **Remove excessive indexes**: Unnecessary indexes can degrade write performance

  ```sql
  -- Check unused indexes
  SELECT * FROM sys.schema_unused_indexes;

  -- Drop an index
  DROP INDEX idx_unused ON table_name;
  ```

### Slow Query Optimization

**Identifying and addressing slow queries**:

- **Enable and analyze Slow Query Log**

  ```sql
  -- Enable Slow Query Log
  SET GLOBAL slow_query_log = 'ON';
  SET GLOBAL long_query_time = 1; -- Log queries taking longer than 1 second
  SET GLOBAL slow_query_log_file = '/var/log/mysql/mysql-slow.log';

  -- Use analysis tools (e.g., pt-query-digest)
  pt-query-digest /var/log/mysql/mysql-slow.log
  ```

### Connection Pooling

**Optimizing database connection management**:

- **Benefits**: Reduces overhead of connection creation/destruction
- **Implementation options**:
  - Java: HikariCP, C3P0
  - Node.js: mysql2/promise-pool
  - PHP: PDO persistent connections

**Example implementation**:

```javascript
// Example of connection pooling in Node.js
const mysql = require("mysql2/promise");
const pool = mysql.createPool({
  host: "localhost",
  user: "user",
  password: "password",
  database: "db_name",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});
```

## 3. Data Consistency & High Availability

**Problem**: Risk of service interruption due to failures or data loss.

**Solutions**:

### Replication

- **Master-Slave Structure**: Write to master, read from slaves

  ```sql
  -- Master configuration (my.cnf)
  server-id = 1
  log_bin = mysql-bin
  binlog_format = ROW

  -- Slave configuration (my.cnf)
  server-id = 2
  relay_log = mysql-relay-bin
  read_only = ON
  ```

- **Group Replication**: Multiple nodes operating as a group, automatic failure detection
  ```sql
  -- Group Replication setup
  INSTALL PLUGIN group_replication SONAME 'group_replication.so';
  SET GLOBAL group_replication_bootstrap_group = ON;
  START GROUP_REPLICATION;
  ```

### Automatic Failover

**High availability solutions**:

- **Orchestrator**: Modern, widely-used solution with GitHub Certification

**Example configuration**:

```bash
# MHA Manager configuration file example (app1.cnf)
[server default]
user=mha
password=password
ssh_user=root
repl_user=repl
repl_password=slavepass

[server1]
hostname=master.example.com

[server2]
hostname=slave1.example.com
```

### Backup and Recovery Strategy

- **Logical Backup**: SQL dumps using mysqldump

  ```bash
  # Full database backup
  mysqldump -u root -p --all-databases > full_backup.sql

  # Backup specific database
  mysqldump -u root -p my_database > my_database_backup.sql
  ```

- **Physical Backup**: Incremental backups using XtraBackup

  ```bash
  # Full backup
  xtrabackup --backup --target-dir=/backup/full

  # Incremental backup
  xtrabackup --backup --target-dir=/backup/inc1 --incremental-basedir=/backup/full
  ```

## 4. Query Optimization

### Using EXPLAIN Command

- Analyze query execution plans to identify bottlenecks
  ```sql
  EXPLAIN SELECT * FROM users
  JOIN orders ON users.id = orders.user_id
  WHERE users.status = 'active';
  ```

### Query Rewriting

- **Eliminate unnecessary JOINs**: Use subqueries or temporary tables
- **Optimize WHERE conditions**: Modify condition expressions to utilize indexes
- **Use LIMIT**: Restrict result set size

  ```sql
  -- Before optimization
  SELECT * FROM large_table;

  -- After optimization
  SELECT * FROM large_table LIMIT 100;
  ```

### Pagination Optimization

- Use keyset-based pagination instead of offset-based

  ```sql
  -- Inefficient offset method
  SELECT * FROM products ORDER BY id LIMIT 10 OFFSET 1000000;

  -- Efficient keyset method
  SELECT * FROM products WHERE id > 1000000 ORDER BY id LIMIT 10;
  ```

## 5. Hardware & System Configuration

### Server Resource Optimization

- **Memory allocation**: Set `innodb_buffer_pool_size` to 70-80% of total memory

  ```sql
  -- For a 32GB memory server
  SET GLOBAL innodb_buffer_pool_size = 25769803776; -- 24GB
  ```

- **I/O optimization**: Use SSDs, RAID configuration
- **CPU utilization**: Ensure sufficient modern processor cores

### MySQL Configuration Optimization

- Tune `my.cnf` file

  ```ini
  # InnoDB settings
  innodb_buffer_pool_size = 24G
  innodb_log_file_size = 1G
  innodb_flush_log_at_trx_commit = 2

  # Query cache
  query_cache_type = 0  # Deprecated in MySQL 8.0+

  # Connection settings
  max_connections = 500
  thread_cache_size = 32
  ```

### OS Level Optimization

- File system: ext4, XFS
- I/O scheduler: deadline, noop
- Network tuning: TCP settings optimization

## 6. Partitioning

### Table Partitioning

- Divide large tables into smaller units for management
  ```sql
  -- Date-based partitioning example
  CREATE TABLE sales (
    id INT NOT NULL,
    sale_date DATE NOT NULL,
    amount DECIMAL(10,2),
    PRIMARY KEY (id, sale_date)
  )
  PARTITION BY RANGE (YEAR(sale_date)) (
    PARTITION p2021 VALUES LESS THAN (2022),
    PARTITION p2022 VALUES LESS THAN (2023),
    PARTITION p2023 VALUES LESS THAN (2024),
    PARTITION future VALUES LESS THAN MAXVALUE
  );
  ```

### Partition Management

- Add, delete, and reorganize partitions

  ```sql
  -- Add partition
  ALTER TABLE sales ADD PARTITION (PARTITION p2024 VALUES LESS THAN (2025));

  -- Delete partition
  ALTER TABLE sales DROP PARTITION p2021;

  -- Reorganize partition
  ALTER TABLE sales REORGANIZE PARTITION future INTO (
    PARTITION p2024 VALUES LESS THAN (2025),
    PARTITION future VALUES LESS THAN MAXVALUE
  );
  ```

## 7. Advanced Optimization Techniques

### Data Caching Strategies

#### Query Result Caching with Redis

- Cache frequently accessed data or computationally expensive query results

```php
// Example of query result caching with Redis in PHP
function getProductDetails($productId) {
    $redis = new Redis();
    $redis->connect('127.0.0.1', 6379);

    $cacheKey = "product:$productId";
    $cachedResult = $redis->get($cacheKey);

    if ($cachedResult) {
        return json_decode($cachedResult, true);
    }

    // Query DB if not in cache
    $db = new PDO('mysql:host=localhost;dbname=store', 'user', 'password');
    $stmt = $db->prepare("SELECT * FROM products WHERE id = ?");
    $stmt->execute([$productId]);
    $result = $stmt->fetch(PDO::FETCH_ASSOC);

    // Store in cache (valid for 30 minutes)
    $redis->setex($cacheKey, 1800, json_encode($result));

    return $result;
}
```

#### Using Memory Tables

- Store frequently accessed data in memory tables to eliminate I/O bottlenecks

```sql
-- Create a memory table
CREATE TABLE cache_table (
  id INT NOT NULL,
  data VARCHAR(255) NOT NULL,
  PRIMARY KEY (id)
) ENGINE=MEMORY;

-- Insert data
INSERT INTO cache_table
SELECT id, data FROM frequent_access_data;
```

### Large Data Processing Optimization

#### Batch Processing

- Process large volumes of records in batches rather than all at once

```sql
-- Batch deletion example (10,000 records at a time)
SET @batch_size = 10000;
SET @total = (SELECT COUNT(*) FROM old_logs WHERE created_at < '2023-01-01');
SET @processed = 0;

WHILE @processed < @total DO
  DELETE FROM old_logs
  WHERE created_at < '2023-01-01'
  LIMIT @batch_size;

  SET @processed = @processed + ROW_COUNT();
  SELECT SLEEP(0.5); -- Short pause to prevent server overload
END WHILE;
```

#### Using Temporary Tables

- Utilize temporary tables for complex queries or large data processing

```sql
-- Create and index a temporary table
CREATE TEMPORARY TABLE temp_results (
  user_id INT,
  total_orders INT,
  total_amount DECIMAL(10,2),
  INDEX (user_id)
);

-- Store intermediate results
INSERT INTO temp_results
SELECT user_id, COUNT(*), SUM(amount)
FROM orders
WHERE created_at > DATE_SUB(NOW(), INTERVAL 1 MONTH)
GROUP BY user_id;

-- Use temporary table in final query
SELECT u.name, t.total_orders, t.total_amount
FROM users u
JOIN temp_results t ON u.id = t.user_id
WHERE t.total_amount > 1000;
```

### Transaction Optimization

#### Limiting Transaction Size

- Large transactions increase memory usage and lock contention

```sql
-- Wrong approach: One large transaction
START TRANSACTION;
-- Process millions of records
COMMIT;

-- Improved approach: Split into smaller transactions
SET @offset = 0;
SET @limit = 10000;
SET @total = (SELECT COUNT(*) FROM source_table);

WHILE @offset < @total DO
  START TRANSACTION;

  -- Process in batches
  INSERT INTO target_table
  SELECT * FROM source_table LIMIT @offset, @limit;

  COMMIT;
  SET @offset = @offset + @limit;
END WHILE;
```

#### Setting Isolation Levels

- Choose the optimal transaction isolation level for your requirements

```sql
-- Check transaction isolation level
SELECT @@transaction_isolation;

-- For read performance priority
SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED;

-- For data consistency priority
SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ;
```

### MySQL Optimization in Cloud Environments

#### AWS RDS Optimization

- Parameter Group settings

```
# AWS RDS Parameter Group optimization settings
innodb_buffer_pool_size = {DBInstanceClassMemory*0.75}
max_connections = {DBInstanceClassMemory/12582880}
innodb_read_io_threads = 16
innodb_write_io_threads = 16
```

- Using Aurora MySQL
  - Distributed storage system for optimized data I/O
  - Fast replication and failure recovery
  - Serverless option for automatic scaling

#### Monitoring and Performance Analysis

- Utilize AWS CloudWatch and Performance Insights

```bash
# AWS CLI command for DB monitoring
aws cloudwatch get-metric-statistics \
  --namespace AWS/RDS \
  --metric-name CPUUtilization \
  --start-time 2023-05-01T00:00:00Z \
  --end-time 2023-05-01T23:59:59Z \
  --period 3600 \
  --statistics Average \
  --dimensions Name=DBInstanceIdentifier,Value=my-db-instance
```

### Data Compression and Archiving

#### Table Compression

- Save disk space and improve I/O performance

```sql
-- InnoDB table compression
CREATE TABLE compressed_table (
  id INT NOT NULL AUTO_INCREMENT,
  data LONGTEXT,
  PRIMARY KEY (id)
) ENGINE=InnoDB ROW_FORMAT=COMPRESSED KEY_BLOCK_SIZE=8;
```

#### Cold Data Archiving

- Move old data to separate storage

```sql
-- Create archive table
CREATE TABLE orders_archive LIKE orders;

-- Move old data
INSERT INTO orders_archive
SELECT * FROM orders
WHERE order_date < DATE_SUB(CURRENT_DATE, INTERVAL 1 YEAR);

-- Delete moved data from source
DELETE FROM orders
WHERE order_date < DATE_SUB(CURRENT_DATE, INTERVAL 1 YEAR);
```

## 8. Case Studies

### Large Log Table Optimization

**Problem**: Performance degradation in a table accumulating millions of logs daily

**Solution Strategy**:

1. Apply partitioning (daily/monthly data separation)
2. Add indexes for log types
3. Automate cold data archiving

**Implementation Code**:

```sql
-- Create partitioned log table
CREATE TABLE application_logs (
  id BIGINT NOT NULL AUTO_INCREMENT,
  log_timestamp DATETIME NOT NULL,
  log_level ENUM('ERROR', 'WARN', 'INFO', 'DEBUG') NOT NULL,
  service VARCHAR(50) NOT NULL,
  message TEXT,
  PRIMARY KEY (id, log_timestamp)
) PARTITION BY RANGE (TO_DAYS(log_timestamp)) (
  PARTITION p_current VALUES LESS THAN (TO_DAYS(CURRENT_DATE + INTERVAL 1 DAY)),
  PARTITION p_future VALUES LESS THAN MAXVALUE
);

-- Stored procedure for adding monthly partitions
DELIMITER //
CREATE PROCEDURE add_month_partition()
BEGIN
  DECLARE next_month_start DATE;
  DECLARE partition_name VARCHAR(50);

  -- Calculate first day of next month
  SET next_month_start = DATE_ADD(DATE_FORMAT(CURRENT_DATE, '%Y-%m-01'), INTERVAL 1 MONTH);
  SET partition_name = CONCAT('p_', DATE_FORMAT(next_month_start, '%Y_%m'));

  -- Reorganize the last partition
  SET @sql = CONCAT(
    'ALTER TABLE application_logs REORGANIZE PARTITION p_future INTO (',
    'PARTITION ', partition_name, ' VALUES LESS THAN (TO_DAYS(''', next_month_start, ''')),',
    'PARTITION p_future VALUES LESS THAN MAXVALUE)'
  );

  PREPARE stmt FROM @sql;
  EXECUTE stmt;
  DEALLOCATE PREPARE stmt;
END //
DELIMITER ;

-- Event scheduler for automatic partition management
CREATE EVENT add_month_partition_event
ON SCHEDULE EVERY 1 MONTH
STARTS DATE_FORMAT(CURRENT_DATE, '%Y-%m-25')
DO CALL add_month_partition();
```

### High-Traffic E-commerce Platform Optimization

**Problem**: Service disruption due to order surge during sales periods

**Solution Strategy**:

1. Read/write separation (operating 5 Read Replicas)
2. Hot data caching with Redis
3. Implement a queueing system for write operations

**Results**:

- Response time improved by 85% (850ms → 120ms)
- Order processing capacity increased 10x
- Service stability achieved 99.99%

## 9. New Features in MySQL 8.0+

### Window Functions

- Improve analytical query performance

```sql
-- Optimized rank calculation
SELECT
  product_id,
  category_id,
  price,
  RANK() OVER (PARTITION BY category_id ORDER BY price DESC) as price_rank
FROM products;
```

### Common Table Expressions (CTE)

- Improve readability and performance of complex queries

```sql
-- Recursive CTE for hierarchy traversal
WITH RECURSIVE category_tree AS (
  -- Base case: top-level categories
  SELECT id, name, parent_id, 0 AS depth
  FROM categories
  WHERE parent_id IS NULL

  UNION ALL

  -- Recursive case: child categories
  SELECT c.id, c.name, c.parent_id, ct.depth + 1
  FROM categories c
  JOIN category_tree ct ON c.parent_id = ct.id
)
SELECT * FROM category_tree
ORDER BY depth, name;
```

### Histogram Statistics

- Enable more accurate execution plans by the query planner

```sql
-- Create histogram
ANALYZE TABLE orders UPDATE HISTOGRAM ON order_status WITH 10 BUCKETS;

-- Check histograms
SELECT * FROM information_schema.column_statistics
WHERE table_name = 'orders' AND column_name = 'order_status';
```

## 10. Key Performance Monitoring Metrics

### Essential Monitoring Metrics

- **Query Response Time**: Monitor 95th, 99th percentiles
- **InnoDB Buffer Pool Hit Rate**: Aim to maintain above 99%
- **Connections**: Keep below 70% of maximum connections
- **Disk I/O**: IOPS, latency, throughput
- **Temporary Table Usage**: Minimize disk-based temporary tables

### Monitoring Tools

- **MySQL Enterprise Monitor**
- **Prometheus + Grafana**
- **Percona Monitoring and Management (PMM)**
- **SolarWinds Database Performance Analyzer**

```sql
-- Query to check resource usage
SELECT * FROM performance_schema.memory_summary_global_by_event_name
WHERE event_name LIKE 'memory/innodb/%'
ORDER BY current_alloc DESC LIMIT 10;

-- Check slow queries
SELECT * FROM performance_schema.events_statements_summary_by_digest
ORDER BY sum_timer_wait DESC LIMIT 10;
```

## Conclusion

MySQL database optimization requires a comprehensive approach that considers architecture design, infrastructure configuration, and operational management beyond simple query tuning. Optimization is not a one-time task but a continuous process requiring ongoing monitoring and improvement.

Based on the various strategies and techniques presented in this guide, design and implement optimization measures tailored to the characteristics of your applications and business needs. Improved database performance leads to better service responsiveness, user experience, and ultimately, business outcomes.

## References

- [MySQL Official Documentation - Performance Optimization](https://dev.mysql.com/doc/refman/8.0/en/optimization.html)
- [High Performance MySQL (O'Reilly)](https://www.oreilly.com/library/view/high-performance-mysql/9781492080503/)
- [MySQL Performance Blog](https://www.percona.com/blog/)
