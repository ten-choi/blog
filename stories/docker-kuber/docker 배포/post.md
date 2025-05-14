desktop docker 를 통해서 도커 사용법을 연마하자
먼저 다운로드를 받아준다

docer -v 로 버전나오면 문제없는거다

docker pull reids 로 테스트를 해본다
docker pull nginx:latest

왼쪽(안쪽)이 호스트 포트 외부접근하는 포트이고 오른쪽이 컨테이너 내부 포트이다.
docker run -d -p 8080:8080 으로 하면 내부포트 외부포트가 8080이기때문에 8080으로 접근가능하다 -d는 디테치 분리하다 라는 뜻으로 백그라운드에 분리하여 실행하게 하기위한 태그 이다.

아래 처럼 이름도 설정할수있다.
sudo docker run --name mynginx -p 7070:70 -d nginx:latest

pull을 했을경우 아래 명령어로 어떤 이미지를 가지고있는지 알수있다
docker images

실행하면 run중인거는 ps기능으로 실행 가능하다
docker ps

-d detach를 통해 로그를 못봤다면 아래 명령어를 통해 도커를 볼수도있다
docker logs id
docker logs -f id 는 follow모드여서 다시 계속 로그가 보이게함

아래에서 내가 생성한 images의 설정 경로로 접근가능하다 여기서 nginx 설정을 조절하자
sudo docker exec -it mynginx /bin/bash

-it:
-i: 명령어 실행 시 입력을 받을 수 있도록 표준 입력을 활성화합니다.
-t: 가상 터미널을 연결하여 출력 결과를 보기 쉽게 표시합니다.

nginx를 설치했으니

docker file을 만들어보자

`vi Dockerfile`를 해준다

```docker
FROM openjdk:17
WORKDIR /app

# JAR 파일을 컨테이너 내부로 복사합니다.
COPY deploy/build/libs/coconeapphub-0.0.1-SNAPSHOT.jar app.jar

# 애플리케이션 실행
ENTRYPOINT ["java", "-jar", "app.jar"]

```

이미지를 위처럼 등록한다

`docker build -t myjava .`
빌드하면

`docker images` 를 하면 레포지토리 명이 보인다

아래 코드를 실행하자 이미지를 가지고 런하는 친구는 runmyjava로 만들어주자

런하는 곳까지 올리면 컨테이너 라고한다

`sudo docker run --name runmyjava -p 443:443 myjava2:latest`

run을 하는경우 성공하는 경우와 실패하는 경우가 있다 실패하는

jar파일 업로드를 해 여기서 images에 등록하고 잘 실행되나 테스트 해보자

문제가 없다면 이제 jenkins에서 이짓을 해보자

run에 실패하는경우
docker ps -a 로 검색하면 실행 종료된 docker도 나오기때문에 docker rm `container id` 로 삭제해주자

aws configure가 필요한 경우 직접 설정하여 넣어주면 실행가능하다

docker run -e AWS_ACCESS_KEY_ID=asdfasdf -e AWS_SECRET_ACCESS_KEY=asfasfdasdfasdf -e AWS_REGION=ap-northeast-1 --name runmyjava4 -p 6060:60 myjava2:latest

위처럼하여 nginx, java를 실행했다면 그다음은 jenkins에서 위와같은 방식을 사용해 배포가 되게끔하고싶다
즉 build파일을 배포하는게 아니라 images파일을 배포하고 restart하는 방식을 채택하고싶다

먼저 docker가 설치되어 container를 재기동하는건 변함없다 이걸 하고 jenkins에서 요청하는거 하고 그거 테스트 끝나면 다음주에 리펙토링 핑계대면서 전체적으로 손한번 보면 마무리 될듯
그리고 수정할거있으면 수정요청하고

바로 된다고하지말고 알아도 봐본다고 하기
어떻게될지 모름

nginx

    access_log  /var/log/nginx/access.log  main;

    client_max_body_size 1000M;
    sendfile            on;
    tcp_nopush          on;
    keepalive_timeout   65;
    types_hash_max_size 4096;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

    # Load modular configuration files from the /etc/nginx/conf.d directory.
    # See http://nginx.org/en/docs/ngx_core_module.html#include
    # for more information.
    include /etc/nginx/conf.d/*.conf;

    server {
        listen       443;
        listen       [::]:443;
        server_name  _;
        root         /usr/share/nginx/html;

        # Load configuration files for the default server block.
        include /etc/nginx/default.d/*.conf;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

`sudo docker run --name mynginx2 -p 443:443 nginx:latest`

sudo docker exec -it mynginx2 /bin/bash

1. 실행 중인 모든 컨테이너 중지
   bash
   Copy code
   sudo docker stop $(docker ps -q)
2. 모든 컨테이너 삭제
   bash
   Copy code
   sudo docker rm $(docker ps -a -q)

docker의 docker 파일에 대해 엄청난걸 깨달아버렸다.

FROM node14
이거부터 시작하하는 도커파일의

COPY는 진짜 파일의 내용을 복사한다는거였다.

해당 디렉토리에 해당위치에 카피해서 실행한다 이제야 도커를 조금 이해했다.

docker 네트워크는 nginx의 역할과 비슷한듯 하다

docker network create redis-cluster

d는 백그라운드 --name은 이름설정 -net은 네트워크 설정

-v는 볼륨 마운트 -> 내 로컬 파일을 docker의 redis에 적용
첫번째 p는 외부 접근용 2번째 p는 노드끼리 내부 연결용
마지막 redis 는 run할 주체이고 그뒤는 그 주체를 실행할 정보

docker run -d --name redis-7002 --net redis-cluster -v C:\workSpace\projects\redis-cluster\7002\redis.conf:/usr/local/etc/redis/redis.conf -p 7002:7002 -p 17002:17002 redis:latest redis-server /usr/local/etc/redis/redis.conf

도커 실행
docker exec -it redis-7000 redis-cli --cluster create 127.0.0.1:7000 127.0.0.1:7001 127.0.0.1:7002 --cluster-replicas 0

exec: 실행 중인 컨테이너에서 명령어를 실행
-it:
-i: 명령어 실행 시 입력을 받을 수 있도록 표준 입력을 활성화합니다.
-t: 가상 터미널을 연결하여 출력 결과를 보기 쉽게 표시합니다.
redis-7000: 명령을 실행할 컨테이너 이름입니다. 여기서는 Redis 노드 중 하나인 redis-7000 컨테이너에서 명령을 실행합니다.

실행 잘됬는지 확인
docker exec -it redis-7000 redis-cli cluster nodes

1. 기본적으로 이미지 컨테이너로 기본관리함
2. 볼륨이라는 외부 저장소 하나를 만들고 마운트 하는것을 배움 -> 로그 파일같은거 이쪽에 뺄수도있음
3. 그러면 이제 네트워크의 개념을 배움 하나의 네트워크에 연결하는용도로

docker 로 배포하는 경우 자동화를 위해 dockerfile 과 docker-compose를 설정한다
그리고 mongodb같은걸 사용하는경우 network를 하나로해야하나는데 이경우 localhost를 사용할수없다
몽고와 go server는 다른 컨테이너로 가정할경우 localhost는 본인 컨테이너의 27017 을 바라보는게 기본으로 설정이되버린다

그렇기때문에 network에 설정된 이름을 보고 그이름과 동일하게 localhost가 아닌 e.g) mongoDbUrl 이런거로 설정이 되있는경우 소스코드에서도
그값을 사용해야한다
그래야 별도의 컨테이너에서 값을 가져오려하기때문이다

nginx는 이제 별도의 설정할게 없어서 필요가 없다고 판단했다

mongodb 와 golang server를 실행하려고한다

Dockerfile과 docker-compose.yml 파일이 필요했다
DockerFile은 어떤 이미지를 빌드할지를 설정하는 파일이며 이 파일이 결국

DockerFile은 어떤 이미지를 빌드할지를 설정하는 파일이며 이 파일이 이미지를 만듦

docker-compose.yml 은 설정한 Dockerfile들을 가지고 네트워크 이런것도 설정해서 여러개의 컨테이너를 한번에 실행하거나 관리하는 설정이 가능

즉 Dockerfile은 이미지 빌드

docker-compose.yml은 실행관련 설정이라고 볼수있다

.env 는 Makefile로 관리하면된다

mongodb같은경우에는 localhost를 사용할수없기때문에 local이 아닌경우에는 그것에 맞는 설정이 별도로 필요할듯하다

그리고 compose에서도 mongo를 같이 실행하기보단 몽고를 실행하는 코드는 별도로 준비하여 해당 네트워크안에서 실행되는것만 남겨도될듯하다
안그러면 나중에 mongo쪽이 리빌드 되거나 무언가 변경사항이 생겼을때 내부 정보가 유실 될 가능성이있다

이렇게 하면 docker에서 실행하는것은 문제가 없다
