---
title: 아파치 웹 서버와 톰캣 설치 및 연동 가이드
date: 2025-05-30
published: true
description: Apache HTTP 서버와 Apache Tomcat을 설치하고 연동하는 방법에 대한 포괄적인 가이드
tags: apache, tomcat, web-server, was, java
cover_image: https://upload.wikimedia.org/wikipedia/commons/thumb/7/7e/Apache_Feather_Logo.svg/1200px-Apache_Feather_Logo.svg.png
series: 웹 서버 시리즈
---

# 아파치 웹 서버와 톰캣 설치 및 연동 가이드

## 목차

- [아파치 웹 서버와 톰캣 설치 및 연동 가이드](#아파치-웹-서버와-톰캣-설치-및-연동-가이드)
  - [목차](#목차)
  - [개요](#개요)
## 개요

아파치 버전 Server version: Apache/2.4.63 (Unix)

key, pem 관련된 파일로 인증 파일을 만든다
server.xml에 443 포트 접근과 해당 인증파일및 비밀번호를 사용한 커넥터를 추가한다

er built:   Jun 5 2025 17:49:55 UTC
Server number:  11.0.8.0
OS Name:        Linux
OS Version:     6.1.134-150.224.amzn2023.x86_64
Architecture:   amd64
JVM Version:    17.0.15+6-LTS


이 스펙 기준이다

정답은 11.0.8 정도 되면 이제 ssl을 적용하는 방식이 달라진다고 한다

아래처럼 적용해야한다고 한다

```xml
<Connector port="8443"
           protocol="org.apache.coyote.http11.Http11NioProtocol"
           address="0.0.0.0"
           SSLEnabled="true">
  <UpgradeProtocol className="org.apache.coyote.http2.Http2Protocol" />
  <SSLHostConfig protocols="TLSv1.3,TLSv1.2">
    <Certificate
      certificateKeystoreFile="/usr/local/tomcat/ssl/test.jp.p12"
      certificateKeystoreType="PKCS12"
      certificateKeystorePassword="testpw"
      type="RSA" />
  </SSLHostConfig>
</Connector>
```


LOG를 보면서 나머지는 그냥 진행하면된다 TOMCAT버전을 기준으로 잘 진행하면 문제없다
도커에서 network띄우고 아파치와 tomcat둘다 적용하는게 좋을듯하다


docker폴더만들어서 tomcat과 apache 관련 dockerfile을 생성한다
build후 각각의 이미지를 생성한다 


common-apache[master]
apache.conf( common conf file for include)
　↳　alpha
　　↳　HANGAME-GAME-ALPHA1-64
　　　↳　server 1
　　　  ↳　dockerfile
　　　  ↳　hange-alice
  　　　  ↳　apache
    　　　  ↳　conf
      　　　  ↳　httd.conf
　　　  ↳　hange-shop
  　　　  ↳　apache
    　　　  ↳　conf
      　　　  ↳　httd.conf
　　　  ↳　hange-llilian
  　　　  ↳　apache
    　　　  ↳　conf
      　　　  ↳　httd.conf




tomcat 에서 apache의 redirect설정을 추가하는법 
이걸 server.xml 에적용해야함
<Valve className="org.apache.catalina.valves.rewrite.RewriteValve" />

이렇게 적용했을때는 성공했다
     -v '/home/www/yeoltest/rewrite.config:/usr/local/tomcat/conf/Catalina/localhost/rewrite.config:ro' \

하지만 그리고 아래의 rewrite설정을 적용한다
src/main/webapp/WEB-INF/rewrite.config 로 옮기세요.
