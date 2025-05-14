# MySQL 성능 최적화 완벽 가이드

MySQL은 가장 인기 있는 관계형 데이터베이스 중 하나지만, 대규모 애플리케이션이나 고트래픽 환경에서는 성능 이슈가 발생할 수 있습니다. 이 문서는 MySQL 데이터베이스의 성능을 최적화하기 위한 전략과 기법을 제공합니다.

## 목차

1. [확장성(Scalability)](#1-확장성-scalability)
2. [성능 최적화(Performance Optimization)](#2-성능-최적화-performance-optimization)
3. [데이터 일관성 및 고가용성(Data Consistency & High Availability)](#3-데이터-일관성-및-고가용성-data-consistency--high-availability)
4. [쿼리 최적화(Query Optimization)](#4-쿼리-최적화-query-optimization)
5. [하드웨어 및 시스템 설정(Hardware & System Configuration)](#5-하드웨어-및-시스템-설정-hardware--system-configuration)
6. [파티셔닝(Partitioning)](#6-파티셔닝-partitioning)
7. [추가 고급 최적화 기법](#7-추가-고급-최적화-기법)
8. [실제 사례 연구](#8-실제-사례-연구)
9. [MySQL 8.0+ 신규 기능 활용](#9-mysql-80-신규-기능-활용)
10. [주요 성능 모니터링 지표](#10-주요-성능-모니터링-지표)

## 1. 확장성 (Scalability)

**문제**: 단일 인스턴스 MySQL은 처리할 수 있는 트래픽과 데이터량이 제한적입니다.

**대응**:

### 수직 확장 (Vertical Scaling)

- 더 강력한 CPU, 메모리, 스토리지를 갖춘 서버로 업그레이드
- 장점: 구현이 간단함
- 단점: 확장에 한계가 있으며 비용이 기하급수적으로 증가

### 수평 확장 (Horizontal Scaling)

- **Read Replica 설정**: 읽기 트래픽을 여러 복제본으로 분산

서버 2개를 준비한다

/etc/mysql/my.cnf에 아래의 값을 변경하거나 추가한다

```
server-id = 1        # 서버간 중복금지
log_bin = mysql-bin  # 복제를위해 필수 log
binlog_format = ROW  # 일반적으로 row를 권장한다고한다
```

사용자를 생성하고 레플리카를 생성가능한 권한을 부여한다
그리고 권한을 적용한다

```ddl
CREATE USER 'replication_user'@'%' IDENTIFIED BY 'password';
GRANT REPLICATION SLAVE ON *.* TO 'replication_user'@'%';
FLUSH PRIVILEGES;
```

SHOW MASTER STATUS;
위 코드로 현재 상태를 확인한다 문제가없다면 기존의 master데이터를 dump받아서 replica에 복붙한다

```ddl
mysqldump -u root -p --all-databases --master-data=2 --single-transaction > dump.sql
mysql -u root -p < dump.sql
```

그리고 replica의 server-id는 master와 다르게 설정한다

아래의 코드로 slave의 db를 master를 보게하고 slave를 시작한다

```ddl
CHANGE MASTER TO
  MASTER_HOST='master_host_ip',         -- Master 서버의 IP 또는 도메인 주소 설정
  MASTER_USER='replication_user',       -- Master에서 생성한 복제 전용 사용자 계정
  MASTER_PASSWORD='password',           -- 복제 전용 사용자의 비밀번호
  MASTER_LOG_FILE='mysql-bin.000001',   -- Master에서 SHOW MASTER STATUS로 확인한 현재 Binlog 파일명
  MASTER_LOG_POS=107;                   -- SHOW MASTER STATUS에서 확인한 Binlog 내 복제 시작 위치 (바이트 단위 오프셋)

START SLAVE;  -- 또는 START REPLICA; (버전에 따라 다름)
```

proxySql을 사용하면 읽기/쓰기 분리 및 로드 밸런싱을 해야하는데 master slave가 아닌 새로운서버에서 로드밸런서처리를 한다고한다

```bash
# ProxySQL 설정 예시
UPDATE mysql_servers SET weight=10 WHERE hostname='reader1';
UPDATE mysql_servers SET weight=5 WHERE hostname='reader2';
LOAD MYSQL SERVERS TO RUNTIME;
```

비용은 더많이 드는방법이지만 아래와같은 이유로 사용할수있다

✅ ProxySQL을 써야 하는 상황
🟢 1. 애플리케이션이 단순하게 동작하길 원할 때
애플리케이션이 읽기/쓰기 분리나 복제 서버 관리를 몰라도 되게 하고 싶을 때.

비즈니스 로직은 오직 ProxySQL 하나만 바라보면 되기 때문.

🟢 2. Replica가 많고 부하 분산이 필요할 때
Replica가 3대 이상이거나 가중치 기반으로 부하를 자동 분산하고 싶을 때.

예: 어떤 Replica는 50%, 어떤 Replica는 30%, 어떤 Replica는 20%.

🟢 3. 운영팀이 트래픽 제어를 빠르게 하고 싶을 때
서버 추가/삭제, 가중치 변경 등을 애플리케이션 수정 없이
ProxySQL 설정만 바꿔서 실시간 반영하고 싶을 때.

🟢 4. 복제 장애 대응이나 장애 전환(HA)이 필요할 때
ProxySQL + Orchestrator 같은 툴을 함께 쓰면
장애 자동 감지 및 전환이 가능.

### 샤딩 (Sharding)

mysql일 경우 시스템에서 지원해주지않기때문에 특정값을 기준으로 application이나 middleware에서 걸러줘야한다
시스템에서 지원해주지않는다면 샤딩을 할필요는 없다고 본다

- 데이터를 여러 서버에 분산 저장 (수평 파티셔닝)
- 구현 방법:
  - 범위 기반 샤딩 (Range-Based)
  - 해시 기반 샤딩 (Hash-Based)
  - 디렉토리 기반 샤딩 (Directory-Based)

```sql
-- 샤드 1의 테이블 예시 (사용자 ID 1-1000000)
CREATE TABLE users_shard1 (
  id INT PRIMARY KEY,
  name VARCHAR(100),
  /* 기타 필드 */
  CONSTRAINT check_id CHECK (id BETWEEN 1 AND 1000000)
);

-- 샤드 2의 테이블 예시 (사용자 ID 1000001-2000000)
CREATE TABLE users_shard2 (
  id INT PRIMARY KEY,
  name VARCHAR(100),
  /* 기타 필드 */
  CONSTRAINT check_id CHECK (id BETWEEN 1000001 AND 2000000)
);
```

## 2. 성능 최적화 (Performance Optimization)

**문제**: 대량의 데이터 처리나 고트래픽 상황에서 쿼리 성능 저하.

**대응**:

### 인덱스 최적화

일반적으로 b-tree를 사용한다
인덱스를 주로 추가해서 설정하는데 간단한 프로그램인데 read가 많을경우 넣기 좋다

- **적절한 인덱스 설계**: 자주 사용되는 WHERE, JOIN, ORDER BY 절의 컬럼에 인덱스 생성

  ```sql
  -- 기본 인덱스 생성
  CREATE INDEX idx_last_name ON users(last_name);

  -- 복합 인덱스 생성
  CREATE INDEX idx_last_first_name ON users(last_name, first_name);

  -- 인덱스 상태 확인
  SHOW INDEX FROM users;
  ```

- **과도한 인덱스 제거**: 불필요한 인덱스는 오히려 쓰기 성능 저하

  ```sql
  -- 사용되지 않는 인덱스 확인
  SELECT * FROM sys.schema_unused_indexes;

  -- 인덱스 삭제
  DROP INDEX idx_unused ON table_name;
  ```

### Slow Query 최적화

- **Slow Query Log 활성화 및 분석**

  ```sql
  -- Slow Query Log 활성화
  SET GLOBAL slow_query_log = 'ON';
  SET GLOBAL long_query_time = 1; -- 1초 이상 걸리는 쿼리 기록
  SET GLOBAL slow_query_log_file = '/var/log/mysql/mysql-slow.log';

  -- 분석 도구 사용 (예: pt-query-digest)
  pt-query-digest /var/log/mysql/mysql-slow.log
  ```

### Connection Pooling

- 데이터베이스 연결 생성/해제 비용 절감
- 구현:
  - Java: HikariCP, C3P0
  - Node.js: mysql2/promise-pool
  - PHP: PDO persistent connections

```javascript
// Node.js에서 connection pooling 예시
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

## 3. 데이터 일관성 및 고가용성 (Data Consistency & High Availability)

**문제**: 장애나 데이터 손실 발생 시 서비스 중단 위험.

**대응**:

### Replication (복제)

- **Master-Slave 구조**: 쓰기는 마스터, 읽기는 슬레이브로 분산

  ```sql
  -- 마스터 설정 (my.cnf)
  server-id = 1
  log_bin = mysql-bin
  binlog_format = ROW

  -- 슬레이브 설정 (my.cnf)
  server-id = 2
  relay_log = mysql-relay-bin
  read_only = ON
  ```

- **Group Replication**: 여러 노드가 그룹으로 동작, 자동 장애 감지
  ```sql
  -- Group Replication 설정
  INSTALL PLUGIN group_replication SONAME 'group_replication.so';
  SET GLOBAL group_replication_bootstrap_group = ON;
  START GROUP_REPLICATION;
  ```

### 자동 Failover

- **MHA (MySQL High Availability)** 또는 **Orchestrator** 도입

sudo apt-get update
sudo apt-get install -y orchestrator

### 백업 및 복구 전략

- **논리적 백업**: mysqldump를 이용한 SQL 덤프

  ```bash
  # 전체 데이터베이스 백업
  mysqldump -u root -p --all-databases > full_backup.sql

  # 특정 데이터베이스만 백업
  mysqldump -u root -p my_database > my_database_backup.sql
  ```

- **물리적 백업**: XtraBackup을 이용한 증분 백업

  ```bash
  # 전체 백업
  xtrabackup --backup --target-dir=/backup/full

  # 증분 백업
  xtrabackup --backup --target-dir=/backup/inc1 --incremental-basedir=/backup/full
  ```

## 4. 쿼리 최적화 (Query Optimization)

### EXPLAIN 명령어 활용

- 쿼리 실행 계획 분석으로 병목 현상 파악
  ```sql
  EXPLAIN SELECT * FROM users
  JOIN orders ON users.id = orders.user_id
  WHERE users.status = 'active';
  ```

### 쿼리 재작성

- **불필요한 JOIN 제거**: 서브쿼리나 임시 테이블 활용
- **WHERE 조건 최적화**: 인덱스를 활용할 수 있는 조건식으로 변경
- **LIMIT 사용**: 결과셋 크기 제한

  ```sql
  -- 최적화 전
  SELECT * FROM large_table;

  -- 최적화 후
  SELECT * FROM large_table LIMIT 100;
  ```

### 페이지네이션 최적화

- 오프셋 기반보다 키셋 기반 페이지네이션 사용

  ```sql
  -- 비효율적인 오프셋 방식
  SELECT * FROM products ORDER BY id LIMIT 10 OFFSET 1000000;

  -- 효율적인 키셋 방식
  SELECT * FROM products WHERE id > 1000000 ORDER BY id LIMIT 10;
  ```

## 5. 하드웨어 및 시스템 설정 (Hardware & System Configuration)

### 서버 리소스 최적화

- **메모리 할당**: `innodb_buffer_pool_size`를 총 메모리의 70-80%로 설정

  ```sql
  -- 32GB 메모리 서버의 경우
  SET GLOBAL innodb_buffer_pool_size = 25769803776; -- 24GB
  ```

- **I/O 최적화**: SSD 사용, RAID 구성
- **CPU 활용**: 최신 프로세서, 충분한 코어 수 확보

### MySQL 설정 최적화

- `my.cnf` 파일 튜닝

  ```ini
  # InnoDB 설정
  innodb_buffer_pool_size = 24G
  innodb_log_file_size = 1G
  innodb_flush_log_at_trx_commit = 2

  # 쿼리 캐시
  query_cache_type = 0  # MySQL 8.0+ 에서는 deprecated

  # 연결 설정
  max_connections = 500
  thread_cache_size = 32
  ```

### OS 레벨 최적화

- 파일 시스템: ext4, XFS
- I/O 스케줄러: deadline, noop
- 네트워크 튜닝: TCP 설정 최적화

## 6. 파티셔닝 (Partitioning)

### 테이블 파티셔닝

- 대용량 테이블을 작은 단위로 분할하여 관리
  ```sql
  -- 날짜 기반 파티셔닝 예시
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

- 파티션 추가, 삭제, 재구성

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

## 7. 추가 고급 최적화 기법

### 데이터 캐싱 전략

#### Redis를 활용한 쿼리 결과 캐싱

- 자주 조회되는 데이터나 연산 비용이 큰 쿼리 결과를 캐싱

```php
// PHP에서 Redis를 이용한 쿼리 결과 캐싱 예시
function getProductDetails($productId) {
    $redis = new Redis();
    $redis->connect('127.0.0.1', 6379);

    $cacheKey = "product:$productId";
    $cachedResult = $redis->get($cacheKey);

    if ($cachedResult) {
        return json_decode($cachedResult, true);
    }

    // 캐시에 없으면 DB에서 조회
    $db = new PDO('mysql:host=localhost;dbname=store', 'user', 'password');
    $stmt = $db->prepare("SELECT * FROM products WHERE id = ?");
    $stmt->execute([$productId]);
    $result = $stmt->fetch(PDO::FETCH_ASSOC);

    // 결과를 캐시에 저장 (30분 유효)
    $redis->setex($cacheKey, 1800, json_encode($result));

    return $result;
}
```

#### 메모리 테이블 활용

- 자주 조회되는 데이터를 메모리 테이블에 저장하여 I/O 병목 제거

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

- 대량의 레코드를 한 번에 처리하는 대신 배치로 나눠 처리

```sql
-- 배치 삭제 예시 (한 번에 10,000개씩 처리)
SET @batch_size = 10000;
SET @total = (SELECT COUNT(*) FROM old_logs WHERE created_at < '2023-01-01');
SET @processed = 0;

WHILE @processed < @total DO
  DELETE FROM old_logs
  WHERE created_at < '2023-01-01'
  LIMIT @batch_size;

  SET @processed = @processed + ROW_COUNT();
  SELECT SLEEP(0.5); -- 서버 부하 방지를 위한 짧은 휴식
END WHILE;
```

#### 임시 테이블 활용

- 복잡한 쿼리나 대용량 데이터 처리 시 임시 테이블 활용

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

-- 임시 테이블 활용한 최종 쿼리
SELECT u.name, t.total_orders, t.total_amount
FROM users u
JOIN temp_results t ON u.id = t.user_id
WHERE t.total_amount > 1000;
```

### 트랜잭션 최적화

#### 트랜잭션 크기 제한

- 너무 큰 트랜잭션은 메모리 사용량 증가와 잠금 경합 발생

```sql
-- 잘못된 방식: 하나의 큰 트랜잭션
START TRANSACTION;
-- 수백만 건의 레코드 처리
COMMIT;

-- 개선된 방식: 여러 작은 트랜잭션으로 분할
SET @offset = 0;
SET @limit = 10000;
SET @total = (SELECT COUNT(*) FROM source_table);

WHILE @offset < @total DO
  START TRANSACTION;

  -- 배치 단위로 처리
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

-- 읽기 성능이 중요한 경우
SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED;

-- 데이터 일관성이 중요한 경우
SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ;
```

### 클라우드 환경에서의 MySQL 최적화

#### AWS RDS 최적화

- Parameter Group 설정

```
# AWS RDS Parameter Group 최적화 설정
innodb_buffer_pool_size = {DBInstanceClassMemory*0.75}
max_connections = {DBInstanceClassMemory/12582880}
innodb_read_io_threads = 16
innodb_write_io_threads = 16
```

- Aurora MySQL 활용
  - 분산 스토리지 시스템으로 데이터 IO 최적화
  - 빠른 복제 및 장애 복구
  - 서버리스 옵션으로 자동 스케일링

#### 모니터링 및 성능 분석

- AWS CloudWatch 및 Performance Insights 활용

```bash
# AWS CLI를 이용한 DB 모니터링 명령어
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

- 오래된 데이터를 별도 저장소로 이동

```sql
-- 아카이브 테이블 생성
CREATE TABLE orders_archive LIKE orders;

-- 오래된 데이터 이동
INSERT INTO orders_archive
SELECT * FROM orders
WHERE order_date < DATE_SUB(CURRENT_DATE, INTERVAL 1 YEAR);

-- 원본 테이블에서 이동된 데이터 삭제
DELETE FROM orders
WHERE order_date < DATE_SUB(CURRENT_DATE, INTERVAL 1 YEAR);
```

## 8. 실제 사례 연구

### 대용량 로그 테이블 최적화

**문제 상황**: 하루 수백만 건의 로그가 쌓이는 테이블에서 조회 성능 저하

**해결 전략**:

1. 파티셔닝 적용 (일별/월별 데이터 분리)
2. 로그 유형별 인덱스 추가
3. 콜드 데이터 아카이빙 자동화

**적용 코드**:

```sql
-- 파티셔닝된 로그 테이블 생성
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

-- 월별 파티션 추가 스토어드 프로시저
DELIMITER //
CREATE PROCEDURE add_month_partition()
BEGIN
  DECLARE next_month_start DATE;
  DECLARE partition_name VARCHAR(50);

  -- 다음 달 첫날 계산
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

-- 이벤트 스케줄러를 통한 자동 파티션 관리
CREATE EVENT add_month_partition_event
ON SCHEDULE EVERY 1 MONTH
STARTS DATE_FORMAT(CURRENT_DATE, '%Y-%m-25')
DO CALL add_month_partition();
```

### 고트래픽 전자상거래 플랫폼 최적화

**문제 상황**: 세일 기간 주문 폭주로 인한 서비스 장애

**해결 전략**:

1. 읽기/쓰기 분리 (Read Replica 5대 운영)
2. 핫 데이터 Redis 캐싱
3. 쓰기 작업 큐잉 시스템 도입

**성과**:

- 응답 시간 85% 개선 (850ms → 120ms)
- 처리 가능 주문량 10배 증가
- 서비스 안정성 99.99% 확보

## 9. MySQL 8.0+ 신규 기능 활용

### Window Functions

- 분석 쿼리 성능 개선

```sql
-- 순위 계산 최적화
SELECT
  product_id,
  category_id,
  price,
  RANK() OVER (PARTITION BY category_id ORDER BY price DESC) as price_rank
FROM products;
```

### 공통 테이블 표현식 (CTE)

- 복잡한 쿼리의 가독성과 성능 개선

```sql
-- 재귀적 CTE를 이용한 계층 구조 조회
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

- 쿼리 플래너의 정확한 실행 계획 수립

```sql
-- 히스토그램 생성
ANALYZE TABLE orders UPDATE HISTOGRAM ON order_status WITH 10 BUCKETS;

-- 히스토그램 확인
SELECT * FROM information_schema.column_statistics
WHERE table_name = 'orders' AND column_name = 'order_status';
```

## 10. 주요 성능 모니터링 지표

### 핵심 모니터링 지표

- **쿼리 응답 시간**: 95th, 99th 백분위수 모니터링
- **InnoDB 버퍼 풀 적중률**: 99% 이상 유지 목표
- **Connections**: 최대 연결 수의 70% 이하 유지
- **디스크 I/O**: IOPS, 지연 시간, 처리량
- **임시 테이블 사용량**: 디스크 기반 임시 테이블 최소화

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

MySQL 데이터베이스 최적화는 단순한 쿼리 튜닝을 넘어 아키텍처 설계, 인프라 구성, 운영 관리까지 고려하는 종합적인 접근이 필요합니다. 최적화는 한 번에 끝나는 작업이 아니라 지속적인 모니터링과 개선이 요구되는 과정입니다.

이 가이드에서 제시한 다양한 전략과 기법을 바탕으로, 각 애플리케이션과 비즈니스의 특성에 맞는 최적화 방안을 설계하고 구현하시기 바랍니다. 데이터베이스 성능이 향상되면 서비스 응답성, 사용자 경험, 그리고 결과적으로 비즈니스 성과까지 개선됩니다.

## 참고 자료

- [MySQL 공식 문서 - 성능 최적화](https://dev.mysql.com/doc/refman/8.0/en/optimization.html)
- [High Performance MySQL (O'Reilly)](https://www.oreilly.com/library/view/high-performance-mysql/9781492080503/)
- [MySQL Performance Blog](https://www.percona.com/blog/)
