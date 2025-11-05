도커 하버 사용

docker 로그인으로 하버쪽 어카운트 로그인해야함


이거 되면 이미지 풀은 성공한거
sudo docker pull registry.example.com/default_library/tomcat@sha256:da0f6c7d41cdd3deb1a60b389d767b50eac6f74f20e8067cb741379305c9a303


```
services:
  tomcat:
    image: registry.example.com/default_library/tomcat@sha256:da0f6c7d41cdd3deb1a60b389d767b50eac6f74f20e8067cb741379305c9a303
    ports:
      - "8080:8080"
    volumes:
      - ./webapps:/usr/local/tomcat/webapps
    environment:
      - TZ=Asia/Tokyo
    restart: unless-stopped

```


위의 harbor 로했는데 jdk가 21이라서 아래거로 진행할듯


# Tomcat 11 + JDK 17
sudo docker pull tomcat:11-jdk17

# 실행 테스트 (포트 매핑)
sudo docker run -d --name mytomcat11 -p 8080:8080 tomcat:11-jdk17

# JDK 버전 확인
sudo docker exec -it mytomcat11 java -version


파라미터 스토어 
