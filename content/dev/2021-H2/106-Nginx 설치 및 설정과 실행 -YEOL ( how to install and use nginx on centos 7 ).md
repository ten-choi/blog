---
title: "Nginx 설치 및 설정과 실행 (how to install and use nginx on centos 7)"
labels: ["ETC","ETCLanguage","centos","redhat"]
published: true
date: 2021-10-18T18:03:29+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 106
tistoryUrl: "https://yeolceo.tistory.com/106"
tistoryCategory: "ETC/ETCLanguage"
tistoryTags: ["centos","redhat","centos","centos"]
tistoryPostedAt: "2021-10-18 18:03:29"
language: ko
bloggerPostId: "3838830154328639269"
retitled: true
---
\- 환경

OS : Redhat (Centos) 

### **\- nginx 설치하기**

yum에는 nginx 저장소가 따로 없다고 합니다. 설치하기 위한 정보를 저장소에 추가해야 합니다.

```html
[root@test /]# vi /etc/yum.repos.d/nginx.repo
```

vi 명령어로 nginx.repo 파일을 만들어 주세요.

파일 내부를 아래와 같이 채워주세요.

```html
[nginx]
name=nginx repo
baseurl=http://nginx.org/packages/centos/7/$basearch/
gpgcheck=0
enabled=1
```

\[xxxx\]와 name은 유저가 정하는 이름입니다.

baseurl이 데이터를 호출하기 위한 외부 저장소의 url입니다.

gpg는 프로그램 변조 유무를 검사하는 프로그램입니다.

배포할 때 누군가 악의적인 목적으로 내부 원본과 다른 소스를 배포할 수 있습니다. gpg는 배포자의 서명 or 서명된 파일을 제공합니다. 그런 gpg의 서명 여부를 체크하는 옵션입니다. 활성화 1, 비활성화 0입니다.

enabled은 Yum repo에 추가할지 말지에 대한 설정입니다. 활성화 1, 비활성화 0입니다.

저장소 설정을 끝냈으니 아래의 명령어로 nginx를 설치해줍니다. -y는 설치 중 모든 질문을 yes로 한다는 설정입니다.  

```html
[root@test /]# yum install -y nginx
```

아래의 명령어로 설치가 잘 완료되었는지 확인합니다.

```html
[root@test /]# nginx -v
```

설치가 완료됐다면 아래의 명령어를 한번 실행해주세요 

### **\- nginx 설정하기** 

아래의 경로에서 nginx에서 사용할 conf 파일을 만들어줍니다.

```html
[root@test /]#  vi /etc/nginx/conf.d/default.conf
```

아래와 같이 설정해줍니다.

```html
server {
    listen       53001;
    #listen       [::]:8080;

    #server_name  localhost; # 도메인 주소 넣는부분

    root /usr/dist/; # 배포할 프로젝트 dist 경로
    index index.html index.htm;

    client_max_body_size 100M;

    location / {
        root /usr/dist;
        index index.html;
        try_files $uri $uri/ /index.html; #경로 탐색
    }

    location /graphql { # 그래프큐엘 넣는 부분 다른 API를 넣어도 됨 
        proxy_pass http://주소:54001/graphql;
    }

    error_page 404 /404.html;
        location = /40x.html {
    }

    error_page 500 502 503 504 /50x.html;
        location = /50x.html {
    }
}
```

본인이 원하는 root 경로를 지정하세요. 해당 root 위치에 dist forder ( 본인의 front build folder )를 준비하세요.

그리고 아래의 명령어로 nginx.conf를 봅니다. 이게 메인 configuration이며 여기서 default.conf를 호출하는 개념입니다.

```html
[root@test /]#  vi /etc/nginx/nginx.conf
```

스크롤을 진행하면서 아래와 같은 include 부분이 나오는 부분부터 진행해주세요.

```html
include /etc/nginx/conf.d/*.conf; # 이부분이 conf 붙은 모든파일을 불러오는부분

아래에 있는 서버로 되있는부분은 #으로 주석처리 해줍시다. 
(쓰지않을 80포트가 문제가 될수있어요.)
   # server {
   #     listen       80;
   #     listen       [::]:80;
   #     server_name  _;
   #     root         /usr/share/nginx/html;

   ...
   ...
   ...

   # }
```

아래의 명령어를 입력해 주시면 nginx가 실행이 된 겁니다. 기본적으로 실행 중일 수도 있지만 명령어로 한 번 더 확인해주세요.

```html
[root@test /]#   systemctl start nginx
```

만약 방화벽을 설정하지 않았다면 접속할 포트를 지정해줍니다.

```html
[root@test /]#  sudo firewall-cmd --list-ports
[root@test /]#  sudo firewall-cmd --permanent --zone=public --add-port=53001/tcp
[root@test /]#  sudo firewall-cmd --reload
```

외부에서 nginx에 접속하실 때 접속 가능한 http://your access ip:port 해서 접속해주시면 됩니다.

고생하셨습니다. 성실한 코딩 하세요.
