도커와 이것저것 테스트

일단 도커에서 mysql 실행하기

docker run --name mysql -e MYSQL_ROOT_PASSWORD=cnnchoiyeol -d -p 3306:3306 mysql:latest

ScyllaDB를 Docker에서 실행할 때 기본적으로 사용하는 포트는 다음과 같습니다:

CQL 클라이언트 포트: 9042

이 포트는 ScyllaDB와 클라이언트(예: cqlsh, 애플리케이션 등) 간의 통신에 사용됩니다.
내부 관리 포트: 9180

이 포트는 ScyllaDB의 HTTP API와 관련된 요청(예: 클러스터 상태 확인)에 사용됩니다.
JMX 포트: 7199

JMX(Java Management Extensions) 포트는 ScyllaDB의 관리 및 모니터링에 사용됩니다.

docker pull scylla:latest

sudo docker images

docker ps

pull한 nginx이미지를 사용하여 내 서버에서 run할 이미지 하나를 만들어준다

docker run --network=mynetwork --name scylla -d -p 9042:9042 -p 9180:9180 -p 7199:7199 scylladb/scylla

위에 실행한다

실제로 코드를 입력하려면 아래의 코드로 scylla에 접근해야한다
docker exec -it scylla cqlsh

CREATE KEYSPACE my_keyspace WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1};

USE my_keyspace;

CREATE TABLE users (
id UUID PRIMARY KEY,
name TEXT,
age INT
);

INSERT INTO users (id, name, age) VALUES (uuid(), 'John Doe', 30);

SELECT \* FROM users;
