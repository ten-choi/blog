# how to do airflow

에어 플로우를 실행해보았다
젠킨스와 비슷 한개념으로 생각했지만 cicd 툴이라기보단 파이프라인을 관리하는 툴이었다

에어 비엔비가 개발한 워크플로우 스케줄링, 모니터링 플랫폼이다

워크플로우 에서 주기적으로 실행되야하는 크론스크립트가 존재한다면 기존의 간편한 방식에는 문제점이 있다

실패 복구: 언제 어떻게 다시 실행할 것인지, 백필(Backfill)은 어떻게 할 것인지에 대한 문제가 있었다.
모니터링: 잘 돌아가고 있는 지 확인하기 힘들었다.
의존성 관리: 데이터 파이프 라인 간 의존성이 있는 경우 상위 데이터 파이프 라인이 잘 돌아가고 있는 지 파악이 힘들었다.
확장성: 중앙화해서 관리하는 툴이 없기 때문에 분산된 환경에서 파이프 라인을 관리하기 힘들었다.
배포: 새로운 워크 플로우를 배포하기 힘들었다.

그래서 에어플로우로 통합관리하는것이다
큰회사에서 파이프라인이 여러개일경우 모두가 파이프라인을 별도로 관리한다면 리소스가 굉장히 낭비된다

워크플로우와 대그가 연결되어있다
DAG(Directed Acyclic Graph) 대그라고한다

에어플로우의 구성은 아래와 같다
웹 서버: 웹 대시보드 UI이다.
스케쥴러: 워크 플로우가 언제 실행되는 지 관리한다.
메타스토어(Metastore): 메타 데이터를 관리한다.
익세큐터(Executor): 테스크가 어떻게 실행되는 지 정의하는 컴포넌트이다.
워커(Worker): 테스크를 실행하는 프로세스이다.

오퍼레이터(Operator)

하나의 테스크를 정의하는데 사용된다.
액션 오퍼레이터(Action Operators)
실제 연산을 수행한다.
트랜스퍼 오퍼레이터(Transfer Operators)
데이터를 옮긴다.
센서 오퍼레이터(Sensor Operators)
테스크를 언제 실행시킬 지 트리거를 기다린다.

테스크(Task)
오퍼레이터를 실행시키면 테스크가 된다.
테스크는 오퍼레이터 인스턴스이다.

에어플로우의 유용성
데이터 웨어하우스, 머신 러닝, 분석, 실험, 데이터 인프라 관리에서 쓰이게 된다.

version: '3.8'

services:
airflow:
image: apache/airflow:latest
container_name: airflow
restart: always
environment: - AIRFLOW**CORE**EXECUTOR=SequentialExecutor - AIRFLOW**DATABASE**SQL_ALCHEMY_CONN=sqlite:////opt/airflow/airflow.db - AIRFLOW**WEBSERVER**DEFAULT_USER_USERNAME=admin - AIRFLOW**WEBSERVER**DEFAULT_USER_PASSWORD=admin
volumes: - ./airflow:/opt/airflow
ports: - "8085:8085"
command: ["webserver"]
