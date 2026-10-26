---
title: "[ Linux ] 내가 써먹을 Node 배포 과정으로 프론트, 백엔드, DB 환경 설정하기"
labels: ["OS","Linux","환경설정","부하분산","MSA","백엔드","장애대응"]
published: false
date: 2022-04-04T14:59:15+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 129
tistoryUrl: "https://yeolceo.tistory.com/129"
tistoryCategory: "OS/Linux"
tistoryTags: ["환경설정","부하분산","MSA","백엔드","장애대응"]
tistoryPostedAt: "2022-04-04 14:59:15"
language: ko
bloggerPostId: "5276696490903992039"
---
#### 환경 

CentOS Stream 8

#### 개요

CentOS 개발까지 기본 환경 세팅하기이며 제가 볼 용도입니다. 키워드는 다 넣어놓고 부족한 부분은 검색합시다.

#### 목차

-   환경설정
-   위와 같은 진행을 하는 설명글

## **\- 환경설정**

vmware, azure, aws 등에서 centos를 만들어준 상태에서 시작합니다.

방화벽 관련해서는 알아서 뚫어줍시다. 서버는 3개라는 가정하에 진행합니다.

\- 백엔드 서버

먼저 node를 설치합니다.

```html
https://rpm.nodesource.com #아래의 node 설치를 설명해주는 git 사이트

curl -sL https://rpm.nodesource.com/setup_16.x | sudo -E bash #지금 lts인 16버전 설치
yum clean all #캐시 제거
yum install -y nodejs #node 설치
```

node와 npm 확인 및 pm2 설치해줍니다.

```html
node -v #잘 설치되었는지 확인 하고 update 하라고 뜨면하시면됩니다.

npm i -g --save pm2 #서버 무중단 및 클러스터 관리를 위해 pm2 부터 설치
```

\- 프런트 서버

프런트 빌드 파일을 실행할 nginx 설치합니다.

```html
https://www.nginx.com/resources/wiki/start/topics/tutorials/install/  #구글에 nginx install ㄱㄱ
#정해진 경로에 nginx.repo 로 아래의 글을 넣은 파일을 vi로 만들어주면댐
# baseurl 링크는 실제로 들어가서 본인한테 맞게 넣어도 되고 일단 난 centos 8버전이니까 8 넣음
# [root@localhost yum.repos.d]# pwd  -> /etc/yum.repos.d

[nginx]
name=nginx repo
baseurl=https://nginx.org/packages/centos/8/$basearch/ 
gpgcheck=0
enabled=1
```

저장소 등록했으면 설치하고 시작해줍니다.

```html
yum install nginx -y # 설치 ㄱㄱ
systemctl start nginx #시작하기
systemctl enable nginx #nginx 서비스 자동 시작하기
```

\- 데이터베이스

MariaDB 도 위처럼 repo 만들고 설치를 진행합니다.

**[리플리케이션 참조를 할지](https://server-talk.tistory.com/240)** **[클러스터링 갈레라 참조를](https://m.blog.naver.com/PostView.naver?isHttpsRedirect=true&blogId=taemojin&logNo=221577342665)** 할지 고민합시다. 

**[HAProxy참조](https://dev-youngjun.tistory.com/97)** Nginx도 LB가 가능하지만 DB 맞춤형으로 가줍시다.

장애 대응 및 부하분산을 위함입니다.

## **\- 위와 같은 진행을 하는 설명글**

\# nginx는 worker\_processes auto; cpu 돌리고 나중에 scaleout 해서 lb 합시다  
\# pm2는 cluster 여러 개 돌려서 cpu 돌립시다  
\# 둘 다 lb는 aws나 azure 기능으로 하거나 nginx로 lb 가능 pm2도 nginx로 lb 하면 됩니다.  
\# url별로 lb해도 만약 하나의 서버가 터지면 nginx나 클라우드 서비스에서 lb 처리 가능합니다.

\# 무중단 배포에 관련한 좋은 **[링크 참조](https://velog.io/@kakasoo/Node.js%EC%9D%98-Clustering-Module-%EB%A1%9C%EB%93%9C-%EB%B0%B8%EB%9F%B0%EC%8B%B1)**

pm2와 nginx를 이용했지만 기본적으로 프로세스 max로 돌리고 및 LB와 장애 대응, 무중단 배포를 생각해야 합니다.  
유저가 존재하는 서비스 -> 유저가 존재하면 부하분산, 장애 판단이 무조건 돼야 합니다.  
무중단으로 aws 블루 그린이나 도커 언급 안 하는 이유는 aws는 돈이 들고 도커는 쓰는 회사면 쓰세요.

모놀리딕일 때 위처럼 하다가 MSA로 빠지면 비즈니스 도메인별로 분리하고 똑같이 개발하면 됩니다.  
db 쪽은 erd클라우드로 설계 잘하고 스키마 인덱싱도 해줍시다. 

Ngrok 엔그록 사용하기 ->

돈 아까워서 Aws 같은 거 쓰기 싫을 때 VmWare로 서버 3개 돌리고 API 통신 잘 확인한 다음 프런트만 Ngrok 도메인 무료로 연결해주면 외부 접속 가능 즉 내부에서 통신하고 외부 도메인만 무료로 열어준다고 생각하면 됩니다.

근거 있는 조언은 언제나 환영합니다. 성실한 코딩 하세요.
