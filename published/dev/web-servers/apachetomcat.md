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
  - [아파치 웹 서버 (Apache HTTP Server)](#아파치-웹-서버-apache-http-server)
    - [Tomcat Setting](#tomcat-setting)
    - [Apache Setting](#apache-setting)
    - [Apache SSL Setting](#apache-ssl-setting)
    - [Logrotate Setting](#logrotate-setting)
- [added module](#added-module)

## 개요

아파치 HTTP 서버는 정적 콘텐츠를 처리하는 웹 서버이며, 톰캣은 Java 서블릿을 실행하고 JSP를 처리하는 웹 애플리케이션 서버(WAS)입니다. 이 두 서버를 함께 사용하면 정적 콘텐츠와 동적 Java 기반 컨텐츠를 효율적으로 서비스할 수 있습니다.

이 가이드에서는 다양한 운영 체제에서 아파치 웹 서버와 톰캣을 설치하고, 기본적인 설정을 수행하며, 두 서버를 연동하는 방법을 단계별로 설명합니다.

## 아파치 웹 서버 (Apache HTTP Server)

#### Tomcat Setting

i make folder /usr/local/tomcat

1. wget https://downloads.apache.org/tomcat/tomcat-11/v11.0./bin/apache-tomcat-11.0..tar.gz
2. sudo tar -xvzf apache-tomcat-9.0.86.tar.gz -C /usr/local/tomcat
3. cd /usr/local/tomcat/latest/bin
4. sudo chmod +x \*.sh
5. ./startup.sh

check your tomcat link and than cleare you go next

prepare your build file. I'm gonna use test.war

vi /usr/local/tomcat/server.xml
fix this part. if you  
<Context path="/" docBase="/usr/local/test-project" reloadable="false"/>

you need to check your tomcat. if you can see your project. its okay.

remove commentout these module. because you ar gonna use

1. LoadModule proxy_module modules/mod_proxy.so
2. LoadModule proxy_http_module modules/mod_proxy_http.so
3. LoadModule proxy_http_module modules/mod_rerite

in my case i need ajs protocol on tomcat
so i use it

### Apache Setting

i make folder /usr/local/apache

sudo wget https://dlcdn.apache.org/httpd/httpd-2.4.63.tar.gz
sudo tar -xzvf httpd-2.4.63.tar.gz
cd srclib/
sudo wget https://dlcdn.apache.org//apr/apr-1.7.6.tar.gz
sudo wget https://dlcdn.apache.org//apr/apr-util-1.6.3.tar.gz
sudo tar -xzvf
unzip apr, apr-util to folder srclib

give premision
sudo chown -R

./configure --enable-so --enable-ssl --enable-proxy --enable-proxy-ajp --with-apr=/usr/local/apr --with-apr-util=/usr/local/apr-util --prefix=/usr/local/apache

<!-- if you use ajp
./configure --enable-so --enable-ssl --with-apr=/usr/local/apr --with-apr-util=/usr/local/apr-util --enable-mods-shared=all
 -->

make
sudo make install

sudo /usr/local/apache/bin/apachectl start

if you can see localhost:80 on website it okay

### Apache SSL Setting

/usr/local/apache/conf/extra
sudo vi httpd-ssl.conf

if you waana aply ssl on apache, you gonna use ssl such like that.

```
<VirtualHost *:443>

SSLEngine on
SSLCertificateFile /usr/local/ssl/test.crt
SSLCertificateKeyFile /usr/local/ssl/test.key

```

### Logrotate Setting

We should manage logs from tomcat and apache

sudo dnf install logrotate

추가해야함

# added module

LoadModule proxy_module modules/mod_proxy.so
LoadModule proxy_ajp_module modules/mod_proxy_ajp.so
LoadModule ssl_module modules/mod_ssl.so
LoadModule rewrite_module modules/mod_rewrite.so
LoadModule socache_shmcb_module modules/mod_socache_shmcb.so

<VirtualHost \*:80>
ServerName localhost

    RewriteEngine On
    RewriteCond %{REQUEST_URI} \.nhn$
    RewriteRule ^(.*)\.nhn$ /$1 [R=301,L]

    <Proxy "ajp://127.0.0.1:6008/">
     ProxySet secret=myStrongSecret
    </Proxy>

    ProxyPreserveHost On
    ProxyPass / ajp://127.0.0.1:6008/
    ProxyPassReverse / ajp://127.0.0.1:6008/

    ErrorLog /usr/local/apache/logs/error.log
    LogLevel warn rewrite:trace5

</VirtualHost>
