---
title: "Nginx Load Balancing 설정 및 활용 (how to set load balancer on nginx)"
labels: ["ETC","Nginx"]
published: true
date: 2022-01-17T13:48:27+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 119
tistoryUrl: "https://yeolceo.tistory.com/119"
tistoryCategory: "ETC/Nginx"
tistoryTags: ["nginx","nginx","nginx","nginx"]
tistoryPostedAt: "2022-01-17 13:48:27"
language: ko
bloggerPostId: "6814027169277304478"
retitled: true
---
#### 환경 

Linux (Redhat or centos)  
Nginx  

#### 개요

Nginx의 기능을 통해 서버 2대를 이용한 lb test를 진행할 예정입니다.  
\-> load balancing의 약어로 lb라 부르겠습니다.

#### 목차

-   Nginx 설치하기
-   upstream 설정하기
-   Nginx lb 실전 설정을 위한 설계
-   selinux로 인한 보안 문제

### **\- Nginx 설치하기**

패키지 관리 도구 업데이트 및 nginx를 install 해줍니다. dnf로 설치해도 상관없습니다.

```html
sudo yum update -y  
sudo yum install nginx -y
```

설치 완료했다면 **nginx -v** 명령어로 버전을 확인하여 잘 설치된 지 확인해줍니다. 그리고 아래의 이미지와 같은 경로로 이동합니다. pwd는 현재 디렉터리 경로를 보여주는 명령어입니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/119/img.webp)

해당 경로에 존재하는 **nginx.conf**는 **nginx**서버에서 할 행동에 대한 환경설정을 지정하는 파일입니다. **vi nginx.conf** 명령어를 통해 nginx 설정을 확인하거나 수정할 수 있습니다.  **vi nginx.conf** 명령어를 실행해줍니다.

**nginx.conf** 파일의 **default port**를 확인해줍니다. nginx를 설치한 서버의 ip와 nginx에 설정한 default port를 사용해 pc에서 접속해봅니다. 저는 80 포트를 사용 중이라 3001번으로 교체했습니다.

```html
http {

   server {
        listen       3001 default_server; # 80 쓰고있어서 3001로 변경
        root         /usr/share/nginx/html;

    }
}
```

만약 외부에서 접속이 안된다면 방화벽을 해제해줍니다. 서비스에서 방화벽을 멈추고 reload로 잘 멈췄는지 확인해줍니다. 

```dockerfile
systemctl stop firewalld
firewall-cmd --reload
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/119/img_1.webp)

외부 환경인 웹에서 ip를 통해 접근을 시도해주세요.

nginx 기본 화면에 접근이 되셨다면 설치 및 테스트가 완료되었습니다.

### **\- upstream 설정하기**

upstream은 nginx에서 lb를 적용하기 위해 접속할 서버를 등록하는 곳입니다. lb를 어떻게 할지 따로 지정하지 않으면  round robin 방식으로 설정됩니다. 저는 아래의 코드 블록과 같이 upstream명을 lbtest로 설정했습니다.

```html
http {
    upstream lbtest {
        server 준비한 서버 ip:81;
        server 준비한 서버 ip:82;
   }

   server {
        listen       3001 default_server; # 80 쓰고있어서 3001로 변경
        root         /usr/share/nginx/html;

        location /{
           proxy_pass http://lbtest;
        }

        #error_page 404 /404.html;
        #    location = /40x.html {
        #}

        # error_page 500 502 503 504 /50x.html;
        #    location = /50x.html {
        #}
    }
```

실제 이미지는 아래와 같습니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/119/제목 없음.webp)

upstream lbtest에 서버를 2개 이상 등록해줍니다. httpd, node, java 등 접속 가능한 서버면 상관없습니다.

**proxy\_pass**는 외부에서 nginx ip에 접근 시 사용됩니다. proxy\_pass에 입력된 경로에 기존 접근을 우회시켜줍니다. upstream을 따로 설정했다면 upstream에 지정된 서버들을 lb 하면서 호출합니다.

loadbalancing 테스트를 위해 위와 같이 location에 proxy\_pass를 lbtest로 설정합니다.

**주의할 점  
****1\. location /  
**2\. location /test  
**위와 같은 nginx 서버 경로에 같은 upstream ip를 등록해서 사용할 경우 upstream 예시 ip가 111.111.111.111:81일 때** **1번은 설정된 대로 111.111.111.111:81에 접근하지만 2번은 111.111.111.111:81/test에 접근하여 의도하지 않은 접근이 될 수 있습니다.  

**

**\[아래의 예시 코드 블록 참조\]**

```html
http {
    upstream lbtest {
        server 111.111.111.111:81; 
        server 준비한 서버 ip:82;   
   }

   server {
        listen       3001 default_server; # 80 쓰고있어서 3001로 변경
        root         /usr/share/nginx/html;
        location /{
           proxy_pass http://lbtest;
        }

        #######################################
        #location /test{
        #  proxy_pass http://lbtest; 

           #이렇게 할 경우 lbtest에 설정한 ip + 추가된경로 -> 아래와 같은 현상 발생
           #server 111.111.111.111:81/test  

        #}
        ########################################
    }
```

nginx 설정을 완료했다면 restart 명령어를 통해 설정을 적용합니다. reload도 가능하지만 간혹 conf 파일에 오류가 있을 때 restart가 잘 잡아내기 때문에 restart를 애용합니다.

```css
systemctl restart nginx.service
```

nginx를 외부에서 접속하여 새로고침 할 때마다 등록한 서버를 번갈아 띄우는 걸 반복하는지 확인해줍니다.

upstream에 등록되어있는 2개의 url 중 하나를 다운시킨다면 남은하나만 접속됩니다.

loadBalancing 설정 글이지만 유사한 개념인 ServerClustering 부분 또한 테스트하였습니다.

proxy ip를 하나 두고 모든 서버에서 대응하여 문제가 생긴 서버를 제외하고 호출하는 기능도 Nginx upstream과 Azure lb에서 별다른 설정 없이 지원해주는 걸 테스트 결과로 확인했습니다.

### **\- Nginx lb 실전 설정을 위한 설계**

aws나 azure의 lb기능을 사용하지 않는다면 nginx upstream 기능을 통해 lb전용 서버를 만들 수 있습니다. 

nginx 서버를 접속하면 upstream frontLoadBalancer에 등록한 front서버에 접근합니다.

그리고 front에서는 nginx 서버의 graphql에 api를 호출합니다. 그럼 nginx서버는 backLoadBalancer에 등록한 서버에 api를 호출하기 때문에 front와 back의 lb가 가능합니다. 

```html
location /{
           proxy_pass http://frontLoadBalancer;
        }

        location /graphql {
           proxy_pass http://backLoadBalancer;
        }
```

### **\- selinux로 인한 보안 문제**

만약 nginx 접근에 실패하고 nginx error log를 검사하는 경우에서 아래와 같은 문구가 뜰 경우가 있습니다. 

\-> nginx permission denied while connecting to upstream

아래의 명령어를 통해 http 네트워크 연결 상태를 확인해줍니다.

```html
#getsebool -a | grep http
```

httpd\_can\_network\_connect 상태가 off 라면 on으로 바꿔줘야 합니다.

http의 접근 보안정책입니다.

```html
#setsebool httpd_can_network_connect on -P
```

nginx lb에 관한 글이었습니다. 성실한 코딩 하세요.
