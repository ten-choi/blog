---
title: MySQL 성능 최적화
published: false
description: 카테고리 하위 폴더에 게시글 테스트
tags: database, rdb, mysql, optimization
cover_image: https://example.com/your-cover-image.jpg
series: 테스트 시리즈
---

# MySQL 성능 최적화 완벽 가이드

MySQL은 가장 인기 있는 관계형 데이터베이스 중 하나이지만, 대규모 애플리케이션이나 트래픽이 많은 환경에서 성능 문제가 발생할 수 있습니다. 이 문서는 MySQL 데이터베이스 성능을 최적화하기 위한 전략과 기법을 제공합니다.

## 목차

1. [확장성](#1-확장성)
2. [성능 최적화](#2-성능-최적화)
3. [데이터 일관성 및 고가용성](#3-데이터-일관성-및-고가용성)
4. [쿼리 최적화](#4-쿼리-최적화)
5. [하드웨어 및 시스템 구성](#5-하드웨어-및-시스템-구성)
6. [파티셔닝](#6-파티셔닝)
7. [고급 최적화 기법](#7-고급-최적화-기법)
8. [사례 연구](#8-사례-연구)
9. [MySQL 8.0+ 신기능](#9-mysql-80-신기능)
10. [핵심 성능 모니터링 지표](#10-핵심-성능-모니터링-지표)

## 1. 확장성

### 수직 확장(Vertical Scaling)

더 강력한 CPU, 메모리, 저장소가 있는 서버로 업그레이드
장점: 구현이 쉬움
단점: 확장성 제한 및 기하급수적으로 증가하는 비용

### 읽기 복제본 구성

**여러 복제본에 읽기 트래픽을 분산하는 단계**:

1. 두 대의 서버 준비

2. /etc/mysql/my.cnf에서 다음 값을 수정하거나 추가:

```
server-id = 1        # 서버 간 고유해야 함
log_bin = mysql-bin  # 복제에 필요한 로그
binlog_format = ROW  # ROW 형식이 일반적으로 권장됨
```

3. 복제에 필요한 권한이 있는 사용자를 생성하고,
   권한을 적용합니다:

```ddl
CREATE USER 'replication_user'@'%' IDENTIFIED BY 'password';
GRANT REPLICATION SLAVE ON *.* TO 'replication_user'@'%';
FLUSH PRIVILEGES;
```

4. 마스터의 현재 상태 확인:

```sql
SHOW MASTER STATUS;
```

5. 문제가 없다면 기존 마스터 데이터를 덤프하여 복제본에 가져옵니다:

```ddl
mysqldump -u root -p --all-databases --master-data=2 --single-transaction > dump.sql
mysql -u root -p < dump.sql
```

6. 복제본의 server-id를 마스터와 다르게 설정합니다.

7. 슬레이브 데이터베이스가 마스터에 연결하도록 구성하고 슬레이브를 시작합니다:

```ddl
CHANGE MASTER TO
  MASTER_HOST='master_host_ip',         -- 마스터 서버의 IP 또는 도메인 설정
  MASTER_USER='replication_user',       -- 마스터에서 생성된 복제 전용 사용자
  MASTER_PASSWORD='password',           -- 복제 사용자의 비밀번호
  MASTER_LOG_FILE='mysql-bin.000001',   -- SHOW MASTER STATUS의 현재 Binlog 파일명
  MASTER_LOG_POS=107;                   -- SHOW MASTER STATUS의 복제 시작 위치(바이트 오프셋)

START SLAVE;  -- 또는 START REPLICA; (MySQL 버전에 따라 다름)
```

### ProxySQL을 이용한 읽기/쓰기 분리

ProxySQL은 읽기/쓰기 분리 및 부하 분산을 처리하기 위해 마스터 및 슬레이브와 별도의 서버에 구현할 수 있습니다:

```bash
# ProxySQL 구성 예제
UPDATE mysql_servers SET weight=10 WHERE hostname='reader1';
UPDATE mysql_servers SET weight=5 WHERE hostname='reader2';
LOAD MYSQL SERVERS TO RUNTIME;
```

이 접근 방식은 더 많은 리소스를 필요로 하지만 다음과 같은 이유로 사용할 수 있습니다:

**ProxySQL 사용 이점**:

1. **애플리케이션 아키텍처 단순화**:
   애플리케이션은 비즈니스 로직이 ProxySQL에만 연결하면 되므로 읽기/쓰기 분리나 복제 서버 관리를 인식할 필요가 없습니다.

2. **고급 부하 분산 기능**:
   가중치 기반 알고리즘을 사용하여 3개 이상의 복제본으로 작업할 때 효율적으로 부하를 분산합니다.
   예: 트래픽의 50%는 한 복제본으로, 30%는 다른 복제본으로, 20%는 세 번째 복제본으로.

3. **실시간 트래픽 관리**:
   운영 팀은 애플리케이션을 수정하지 않고 ProxySQL 설정만 변경하여 서버를 추가/제거하거나 가중치를 조정할 수 있습니다.

4. **향상된 장애 처리 및 고가용성**:
   Orchestrator와 결합하면 ProxySQL은 자동 장애 감지 및 복구를 가능하게 합니다.

### 샤딩(Sharding)

MySQL은 기본적으로 샤딩을 지원하지 않으므로 특정 값을 기반으로 애플리케이션이나 미들웨어 수준에서 필터링을 구현해야 합니다.
내장된 샤딩 지원이 없는 시스템은 샤딩 구현의 복잡성이 이점을 상회하는지 신중하게 평가해야 합니다.

**샤딩 접근 방식**:

- **데이터 분배**: 여러 서버에 데이터 분산(수평 분할)
- **구현 방법**:
  - 범위 기반 샤딩
  - 해시 기반 샤딩
  - 디렉터리 기반 샤딩

**구현 예제**:

```sql
-- Shard 1 예제 테이블 (사용자 ID 1-1000000)
CREATE TABLE users_shard1 (
  id INT PRIMARY KEY,
  name VARCHAR(100),
  /* 기타 필드 */
  CONSTRAINT check_id CHECK (id BETWEEN 1 AND 1000000)
);

-- Shard 2 예제 테이블 (사용자 ID 1000001-2000000)
CREATE TABLE users_shard2 (
  id INT PRIMARY KEY,
  name VARCHAR(100),
  /* 기타 필드 */
  CONSTRAINT check_id CHECK (id BETWEEN 1000001 AND 2000000)
);
```

## 2. 성능 최적화

**문제**: 대량의 데이터 처리 또는 높은 트래픽 상황에서 쿼리 성능 저하.

**해결책**:

### 인덱스 최적화

**인덱싱 모범 사례**:

- **적절한 인덱스 설계**: WHERE, JOIN 및 ORDER BY 절에서 자주 사용되는 열에 인덱스 생성

  ```sql
  -- 기본 인덱스 생성
  CREATE INDEX idx_last_name ON users(last_name);

  -- 복합 인덱스 생성
  CREATE INDEX idx_last_first_name ON users(last_name, first_name);

  -- 인덱스 상태 확인
  SHOW INDEX FROM users;
  ```

- **과도한 인덱스 제거**: 불필요한 인덱스는 쓰기 성능을 저하시킬 수 있음

  ```sql
  -- 사용되지 않는 인덱스 확인
  SELECT * FROM sys.schema_unused_indexes;

  -- 인덱스 삭제
  DROP INDEX idx_unused ON table_name;
  ```

### 느린 쿼리 최적화

**느린 쿼리 식별 및 해결**:

- **Slow Query Log 활성화 및 분석**

  ```sql
  -- Slow Query Log 활성화b 
  SET GLOBAL slow_query_log = 'ON';
  SET GLOBAL long_query_time = 1; -- 1초 이상 걸리는 쿼리 로깅
  SET GLOBAL slow_query_log_file = '/var/log/mysql/mysql-slow.log';

  -- 분석 도구 사용 (예: pt-query-digest)
  pt-query-digest /var/log/mysql/mysql-slow.log
  ```

### 커넥션 풀링

**데이터베이스 연결 관리 최적화**:

- **이점**: 연결 생성/소멸 오버헤드 감소
- **구현 옵션**:
  - Java: HikariCP, C3P0
  - Node.js: mysql2/promise-pool
  - PHP: PDO 지속 연결

**구현 예제**:

```javascript
// Node.js에서 커넥션 풀링 예제
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

## 3. 데이터 일관성 및 고가용성

**문제**: 장애 또는 데이터 손실로 인한 서비스 중단 위험.

**해결책**:

### 복제

- **마스터-슬레이브 구조**: 마스터에 쓰기, 슬레이브에서 읽기

  ```sql
  -- 마스터 구성(my.cnf)
  server-id = 1
  log_bin = mysql-bin
  binlog_format = ROW

  -- 슬레이브 구성(my.cnf)
  server-id = 2
  relay_log = mysql-relay-bin
  read_only = ON
  ```

- **그룹 복제**: 그룹으로 작동하는 여러 노드, 자동 장애 감지
  ```sql
  -- 그룹 복제 설정
  INSTALL PLUGIN group_replication SONAME 'group_replication.so';
  SET GLOBAL group_replication_bootstrap_group = ON;
  START GROUP_REPLICATION;
  ```

### 자동 장애 조치(Failover)

**고가용성 솔루션**:

- **Orchestrator**: GitHub 인증을 받은 현대적이고 널리 사용되는 솔루션

**구성 예제**:

```bash
# MHA 관리자 구성 파일 예제 (app1.cnf)
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

### 백업 및 복구 전략

- **논리적 백업**: mysqldump를 사용한 SQL 덤프

  ```bash
  # 전체 데이터베이스 백업
  mysqldump -u root -p --all-databases > full_backup.sql

  # 특정 데이터베이스 백업
  mysqldump -u root -p my_database > my_database_backup.sql
  ```

- **물리적 백업**: XtraBackup을 사용한 증분 백업

  ```bash
  # 전체 백업
  xtrabackup --backup --target-dir=/backup/full

  # 증분 백업
  xtrabackup --backup --target-dir=/backup/inc1 --incremental-basedir=/backup/full
  ```

## 4. 쿼리 최적화

### EXPLAIN 명령어 사용

- 쿼리 실행 계획을 분석하여 병목 지점 식별
  ```sql
  EXPLAIN SELECT * FROM users
  JOIN orders ON users.id = orders.user_id
  WHERE users.status = 'active';
  ```

### 쿼리 재작성

- **불필요한 JOIN 제거**: 서브쿼리나 임시 테이블 사용
- **WHERE 조건 최적화**: 인덱스를 ��용하도록 조건식 수정
- **LIMIT 사용**: 결과 집합 크기 제한

  ```sql
  -- 최적화 전
  SELECT * FROM large_table;

  -- 최적화 후
  SELECT * FROM large_table LIMIT 100;
  ```

### 페이지네이션 최적화

- 오프셋 기반 대신 키셋 기반 페이지네이션 사용

  ```sql
  -- 비효율적인 오프셋 방식
  SELECT * FROM products ORDER BY id LIMIT 10 OFFSET 1000000;

  -- 효율적인 키셋 방식
  SELECT * FROM products WHERE id > 1000000 ORDER BY id LIMIT 10;
  ```

## 5. 하드웨어 및 시스템 구성

### 서버 리소스 최적화

- **메모리 할당**: 전체 메모리의 70-80%로 `innodb_buffer_pool_size` 설정

  ```sql
  -- 32GB 메모리 서버의 경우
  SET GLOBAL innodb_buffer_pool_size = 25769803776; -- 24GB
  ```

- **I/O 최적화**: SSD, RAID 구성 사용
- **CPU 활용**: 충분한 최신 프로세서 코어 확보

### MySQL 구성 최적화

- my.cnf 파일 튜닝

  ```ini
  # InnoDB 설정
  innodb_buffer_pool_size = 24G
  innodb_log_file_size = 1G
  innodb_flush_log_at_trx_commit = 2

  # 쿼리 캐시
  query_cache_type = 0  # MySQL 8.0+ 에서 더 이상 사용되지 않음

  # 연결 설정
  max_connections = 500
  thread_cache_size = 32
  ```

### OS 레벨 최적화

- 파일 시스템: ext4, XFS
- I/O 스케줄러: deadline, noop
- 네트워크 튜닝: TCP 설정 최적화

## 6. 파티셔닝

### 테이블 파티셔닝

- 관리를 위해 큰 테이블을 작은 단위로 분할
  ```sql
  -- 날짜 기반 파티셔닝 예제
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

### 파티션 관리

- 파티션 추가, 삭제 및 재구성

  ```sql
  -- 파티션 추가
  ALTER TABLE sales ADD PARTITION (PARTITION p2024 VALUES LESS THAN (2025));

  -- 파티션 삭제
  ALTER TABLE sales DROP PARTITION p2021;

  -- 파티션 재구성
  ALTER TABLE sales REORGANIZE PARTITION future INTO (
    PARTITION p2024 VALUES LESS THAN (2025),
    PARTITION future VALUES LESS THAN MAXVALUE
  );
  ```

## 7. 고급 최적화 기법

### 데이터 캐싱 전략

#### Redis를 사용한 쿼리 결과 캐싱

- 자주 접근하는 데이터 또는 계산 비용이 높은 쿼리 결과 캐싱

```php
// PHP에서 Redis를 사용한 쿼리 결과 캐싱 예제
function getProductDetails($productId) {
    $redis = new Redis();
    $redis->connect('127.0.0.1', 6379);

    $cacheKey = "product:$productId";
    $cachedResult = $redis->get($cacheKey);

    if ($cachedResult) {
        return json_decode($cachedResult, true);
    }

    // 캐시에 없으면 DB 조회
    $db = new PDO('mysql:host=localhost;dbname=store', 'user', 'password');
    $stmt = $db->prepare("SELECT * FROM products WHERE id = ?");
    $stmt->execute([$productId]);
    $result = $stmt->fetch(PDO::FETCH_ASSOC);

    // 캐시에 저장 (30분간 유효)
    $redis->setex($cacheKey, 1800, json_encode($result));

    return $result;
}
```

#### 메모리 테이블 사용

- I/O 병목을 제거하기 위해 자주 접근하는 데이터를 메모리 테이블에 저장

```sql
-- 메모리 테이블 생성
CREATE TABLE cache_table (
  id INT NOT NULL,
  data VARCHAR(255) NOT NULL,
  PRIMARY KEY (id)
) ENGINE=MEMORY;

-- 데이터 삽입
INSERT INTO cache_table
SELECT id, data FROM frequent_access_data;
```

### 대용량 데이터 처리 최적화

#### 배치 처리

- 모든 레코드를 한번에 처리하기보다 대량의 레코드를 배치로 처리

```sql
-- 배치 삭제 예제 (한 번에 10,000개 레코드)
SET @batch_size = 10000;
SET @total = (SELECT COUNT(*) FROM old_logs WHERE created_at < '2023-01-01');
SET @processed = 0;

WHILE @processed < @total DO
  DELETE FROM old_logs
  WHERE created_at < '2023-01-01'
  LIMIT @batch_size;

  SET @processed = @processed + ROW_COUNT();
  SELECT SLEEP(0.5); -- 서버 과부하 방지를 위한 짧은 일시 중지
END WHILE;
```

#### 임시 테이블 사용

- 복잡한 쿼리나 대용량 데이터 처리를 위해 임시 테이블 활용

```sql
-- 임시 테이블 생성 및 인덱싱
CREATE TEMPORARY TABLE temp_results (
  user_id INT,
  total_orders INT,
  total_amount DECIMAL(10,2),
  INDEX (user_id)
);

-- 중간 결과 저장
INSERT INTO temp_results
SELECT user_id, COUNT(*), SUM(amount)
FROM orders
WHERE created_at > DATE_SUB(NOW(), INTERVAL 1 MONTH)
GROUP BY user_id;

-- 최종 쿼리에서 임시 테이블 사용
SELECT u.name, t.total_orders, t.total_amount
FROM users u
JOIN temp_results t ON u.id = t.user_id
WHERE t.total_amount > 1000;
```

### 트랜잭션 최적화

#### 트랜잭션 크기 제한

- 대형 트랜잭션은 메모리 사용량과 잠금 경합을 증가시킴

```sql
-- 잘못된 접근 방식: 하나의 대형 트랜잭션
START TRANSACTION;
-- 수백만 개의 레코드 처리
COMMIT;

-- 개선된 접근 방식: 작은 트랜잭션으로 분할
SET @offset = 0;
SET @limit = 10000;
SET @total = (SELECT COUNT(*) FROM source_table);

WHILE @offset < @total DO
  START TRANSACTION;

  -- 배치 처리
  INSERT INTO target_table
  SELECT * FROM source_table LIMIT @offset, @limit;

  COMMIT;
  SET @offset = @offset + @limit;
END WHILE;
```

#### 격리 수준 설정

- 요구사항에 맞는 최적의 트랜잭션 격리 수준 선택

```sql
-- 트랜잭션 격리 수준 확인
SELECT @@transaction_isolation;

-- 읽기 성능 우선 시
SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED;

-- 데이터 일관성 우선 시
SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ;
```

### 클라우드 환경에서의 MySQL 최적화

#### AWS RDS 최적화

- 파라미터 그룹 설정

```
# AWS RDS 파라미터 그룹 최적화 설정
innodb_buffer_pool_size = {DBInstanceClassMemory*0.75}
max_connections = {DBInstanceClassMemory/12582880}
innodb_read_io_threads = 16
innodb_write_io_threads = 16
```

- Aurora MySQL 사용
  - 최적화된 데이터 I/O를 위한 분산 스토리지 시스템
  - 빠른 복제 및 장애 복구
  - 자동 확장을 위한 서버리스 옵션

#### 모니터링 및 성능 분석

- AWS CloudWatch 및 Performance Insights 활용

```bash
# DB 모니터링을 위한 AWS CLI 명령
aws cloudwatch get-metric-statistics \
  --namespace AWS/RDS \
  --metric-name CPUUtilization \
  --start-time 2023-05-01T00:00:00Z \
  --end-time 2023-05-01T23:59:59Z \
  --period 3600 \
  --statistics Average \
  --dimensions Name=DBInstanceIdentifier,Value=my-db-instance
```

### 데이터 압축 및 아카이빙

#### 테이블 압축

- 디스크 공간 절약 및 I/O 성능 향상

```sql
-- InnoDB 테이블 압축
CREATE TABLE compressed_table (
  id INT NOT NULL AUTO_INCREMENT,
  data LONGTEXT,
  PRIMARY KEY (id)
) ENGINE=InnoDB ROW_FORMAT=COMPRESSED KEY_BLOCK_SIZE=8;
```

#### 콜드 데이터 아카이빙

- 오래된 데이터를 별도 스토리지로 이동

```sql
-- 아카이브 테이블 생성
CREATE TABLE orders_archive LIKE orders;

-- 오래된 데이터 이동
INSERT INTO orders_archive
SELECT * FROM orders
WHERE order_date < DATE_SUB(CURRENT_DATE, INTERVAL 1 YEAR);

-- 이동된 데이터 소스에서 삭제
DELETE FROM orders
WHERE order_date < DATE_SUB(CURRENT_DATE, INTERVAL 1 YEAR);
```

## 8. 사례 연구

### 대용량 로그 테이블 최적화

**문제**: 하루에 수백만 개의 로그가 쌓이는 테이블에서의 성능 저하

**해결 전략**:

1. 파티셔닝 적용(일별/월별 데이터 분리)
2. 로그 유형에 대한 인덱스 추가
3. 콜드 데이터 자동 아카이빙

**구현 코드**:

```sql
-- 파티션 로그 테이블 생성
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

-- 월별 파티션을 추가하는 저장 프로시저
DELIMITER //
CREATE PROCEDURE add_month_partition()
BEGIN
  DECLARE next_month_start DATE;
  DECLARE partition_name VARCHAR(50);

  -- 다음 달의 첫 날 계산
  SET next_month_start = DATE_ADD(DATE_FORMAT(CURRENT_DATE, '%Y-%m-01'), INTERVAL 1 MONTH);
  SET partition_name = CONCAT('p_', DATE_FORMAT(next_month_start, '%Y_%m'));

  -- 마지막 파티션 재구성
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

-- 자동 파티션 관리를 위한 이벤트 스케줄러
CREATE EVENT add_month_partition_event
ON SCHEDULE EVERY 1 MONTH
STARTS DATE_FORMAT(CURRENT_DATE, '%Y-%m-25')
DO CALL add_month_partition();
```

### 고트래픽 이커머스 플랫폼 최적화

**문제**: 세일 기간 동안 주문 급증으로 인한 서비스 중단

**해결 전략**:

1. 읽기/쓰기 분리(5개의 읽기 복제본 운영)
2. Redis를 통한 핫 데이터 캐싱
3. 쓰기 작업을 위한 큐잉 시스템 구현

**결과**:

- 응답 시간 85% 개선(850ms → 120ms)
- 주문 처리 용량 10배 증가
- 서비스 안정성 99.99% 달성

## 9. MySQL 8.0+ 신기능

### 윈도우 함수

- 분석 쿼리 성능 향상

```sql
-- 최적화된 순위 계산
SELECT
  product_id,
  category_id,
  price,
  RANK() OVER (PARTITION BY category_id ORDER BY price DESC) as price_rank
FROM products;
```

### 공통 테이블 표현식(CTE)

- 복잡한 쿼리의 가독성과 성능 향상

```sql
-- 계층 구조 탐색을 위한 재귀적 CTE
WITH RECURSIVE category_tree AS (
  -- 기본 케이스: 최상위 카테고리
  SELECT id, name, parent_id, 0 AS depth
  FROM categories
  WHERE parent_id IS NULL

  UNION ALL

  -- 재귀 케이스: 하위 카테고리
  SELECT c.id, c.name, c.parent_id, ct.depth + 1
  FROM categories c
  JOIN category_tree ct ON c.parent_id = ct.id
)
SELECT * FROM category_tree
ORDER BY depth, name;
```

### 히스토그램 통계

- 쿼리 플래너가 더 정확한 실행 계획을 생성할 수 있도록 지원

```sql
-- 히스토그램 생성
ANALYZE TABLE orders UPDATE HISTOGRAM ON order_status WITH 10 BUCKETS;

-- 히스토그램 확인
SELECT * FROM information_schema.column_statistics
WHERE table_name = 'orders' AND column_name = 'order_status';
```

## 10. 핵심 성능 모니터링 지표

### 필수 모니터링 지표

- **쿼리 응답 시간**: 95%, 99% 백분위수 모니터링
- **InnoDB 버퍼 풀 히트율**: 99% 이상 유지
- **연결**: 최대 연결 수의 70% 이하로 유지
- **디스크 I/O**: IOPS, 지연 시간, 처리량
- **임시 테이블 사용**: 디스크 기반 임시 테이블 최소화

### 모니터링 도구

- **MySQL Enterprise Monitor**
- **Prometheus + Grafana**
- **Percona Monitoring and Management (PMM)**
- **SolarWinds Database Performance Analyzer**

```sql
-- 리소스 사용량 확인 쿼리
SELECT * FROM performance_schema.memory_summary_global_by_event_name
WHERE event_name LIKE 'memory/innodb/%'
ORDER BY current_alloc DESC LIMIT 10;

-- 느린 쿼리 확인
SELECT * FROM performance_schema.events_statements_summary_by_digest
ORDER BY sum_timer_wait DESC LIMIT 10;
```

## 결론

MySQL 데이터베이스 최적화는 단순한 쿼리 튜닝을 넘어 아키텍처 설계, 인프라 구성 및 운영 관리를 고려하는 종합적인 접근 방식이 필요합니다. 최적화는 일회성 작업이 아니라 지속적인 모니터링과 개선이 필요한 프로세스입니다.

이 가이드에서 제시된 다양한 전략과 기법을 바탕으로, 애플리케이션의 특성과 비즈니스 요구에 맞춘 최적화 방안을 설계하고 구현하세요. 향상된 데이터베이스 성능은 서비스 응답성, 사용자 경험, 그리고 궁극적으로 비즈니스 성과로 이어집니다.

## 참고 자료

- [MySQL 공식 문서 - 성능 최적화](https://dev.mysql.com/doc/refman/8.0/en/optimization.html)
- [High Performance MySQL (O'Reilly)](https://www.oreilly.com/library/view/high-performance-mysql/9781492080503/)
- [MySQL Performance Blog](https://www.percona.com/blog/)
