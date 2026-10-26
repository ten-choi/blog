---
title: "[ubuntu] 무작정 docker 실행 해보기"
labels: ["ETC","Docker"]
published: false
date: 2021-02-05T17:05:04+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 83
tistoryUrl: "https://yeolceo.tistory.com/83"
tistoryCategory: "ETC/Docker"
tistoryTags: ["docker","docker","docker","Docker","docker","docker"]
tistoryPostedAt: "2021-02-05 17:05:04"
language: ko
bloggerPostId: "889168884370948342"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/83/img.webp)

#### **\-Docker 란**

애플리케이션을 구축, 테스트, 배포가 용이한 **컨테이너 기반**의 오픈소스 가상화 플랫폼입니다.

-   **컨테이너** : 실행 프로세스가 담겨있으며 컨테이너 자체가 실행 프로세스다 보니 환경에 구애받지 않고  
    수정 배포, 확장이 용이합니다.  

-   **이미지** : 컨테이너를 실행하기 위해 필요한 실행파일, 설정값을 저장한 것입니다.

### **\-**Docker** 실습**

우분투를 **Root** 계정으로 접속해줍니다. (linux의 리소스에 간섭해야 하기 때문에 권한이 필요합니다)

명령어를 통해 **docker**를 다운로드해줍니다.

```html
apt install docker.io
```

-   **도커 작동 방식**

**docker hub**를 통해 image를 사용자의 docker의 **registry**에 다운로드하여 아래 이미지와 같은 프로세스로 동작합니다. 

**\-git**을 사용한 경험이 있다면 유사한 점이 많아 이해하기 수월합니다

![https://www.notion.so/b67ed727aea4467cbc3226bb0c8e8336  출처-재즐보프님의 왕초보 도커 강의](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/83/img_1.webp)

\* **run 명령어**는 pull,, create, start를 한 번에 실행합니다.

**컨테이너**를 실행하기 위한 방법은 **pull, create, start**를 이용해 단계적으로 실행하는 법도 있고

**run** 명령어 하나만으로 실행까지 해 버릴 수도 있습니다.

**docker hub** 에 있는 **nginx**를 이용하여 **다운로드, 실행, 정지, 삭제**까지 해보겠습니다.

#### \-다운로드 및 실행

먼저 **pull, create, start**를 이용하는 단계적 실행법입니다. pull 명령어를 통해 **nginx**를 다운로드합니다.

```html
docker pull nginx
```

다운로드가 완료됐다면 **nginx** **컨테이너**를 만들어줍니다. 

\--name 은 이름을 nx로 설정한다는 의미이고 -p는 port 설정을 하는데 왼쪽의 8080 이 저희가 브라우저에 입력할 포트입니다.

```html
docker create --name nx -p 8080:80 nginx
```

이름 및 포트까지 설정을 완료한 컨테이너를 **start** 명령어를 통해 실행해줍니다.

```html
docker start nx
```

localhost:8080을 웹브라우저의 url로 사용해주세요. 아래와 같이 잘 실행이 되셨나요?

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/83/img_2.webp)

다음은 **run** 명령어를 이용한 방법입니다. 기존의 **nginx**를 컨테이너와 이미지 모두 삭제한 후 

명령어를 입력해보세요!

```html
docker run -d --name nx -p 8080:80 nginx
```

**run**을 통해 한번에 실행이 가능합니다. **localhost:8080**으로 접속해보면 **nginx** 가 실행된 것을 알 수 있습니다.

#### \-정지 및 삭제

**docker**의 **ps** 명령어(process status)를 통해 실행 중인 컨테이너가 있다면 표시해줍니다. **\-a** 옵션(all)을 사용하면 정지 상태인 컨테이너도 터미널에 출력됩니다.

```html
docker ps
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/83/img_3.webp)

저희는 name 설정을 해줬기 때문에 이름을 사용해줍시다. stop 명령어와 rm 명령어를 통해

정지 및 및 컨테이너를 삭제해줍니다.

```html
docker stop nx
```

```html
docker rm nx
```

docker ps -a 명령어를 통해 잘 지워졌는지 확인해줍니다.

그리고 pull 명령어를 통해 다운로드하였던 이미지를 확인해줍니다. 

```html
docker images
```

이미지가 확인이 됐다면 그 이미지의 id를 아래의 명령어에 넣어주고 실행해줍니다. 

```html
docker rmi <IMAGE ID>
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/83/img_4.webp)

apt를 통한 **docker.io install** 부터 컨테이너의 **다운로드, 실행, 정지, 삭제**까지 한 바퀴의 과정을 무작정 돌아보았습니다.

여러분도 한번 실행해보시고 디테일한 부분을 채워나가시기 바랍니다. 

고생하셨습니다 성실한 코딩 하세요.
