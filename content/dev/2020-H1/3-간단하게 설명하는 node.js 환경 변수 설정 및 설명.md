---
title: "간단하게 설명하는 node.js 환경 변수 설정 및 설명"
labels: ["TS","JS","nodejs","환경변수"]
published: false
date: 2020-05-21T10:14:14+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 3
tistoryUrl: "https://yeolceo.tistory.com/3"
tistoryCategory: "TS, JS/nodejs"
tistoryTags: ["환경변수","node.js","node.js"]
tistoryPostedAt: "2020-05-21 10:14:14"
language: ko
bloggerPostId: "8393920036227546440"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/3/img.webp)

node.js의 설치가 완료되었나요? cmd 창 (명령 프롬프트)를 실행합시다.

이번에 해볼 내용은 잘 설치되었는지 혹은 내가 어떤 버전의 node.js를 다운로드하였는지 알아보는 시간입니다.

#### **\-환경변수란**

명령 프롬프트에서 경로에 상관없이 접근 가능한 환경의 변수를 의미합니다. 예를 들어 아래와 같은 명령어는 node.js를 설치한 파일 내에서 명령어를 입력해야 해당하는 기능을 실행합니다. 하지만 환경 변수가 설정되어있다면 node -v라는  
명령어(변수)가 명령 프롬프트 어느 환경(경로)에서도 실행 가능합니다. 아래의 이미지처럼요  

(명령 프롬프트 창을 실행해줄 건데 윈도 10 기준 화면 왼쪽 하단의 윈도 이미지를 누르고 cmd라고 타이핑을 하시면 바로 사용 가능합니다.)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/3/img_1.webp)

환경변수가 설정돼있지 않을 때 node -v를 하는 법 : 본인이 다운로드 한 node.js의 디렉터리 파일의 경로를 복사합니다.

cmd창(명령 프롬프트)에  C:\\Users\\name> cd (복사하신 경로)  하고 엔터 눌러주세요.

경로 폴더 안에 node.exe라는 파일이 있어야 합니다.

후에 node -v를 입력 후 엔터 합니다. node.exe를 실행하는 게 node 명령어이고 -v는 옵션으로서 node.js의 버전을 확인하는 명령어입니다.

명령 프롬프트란 OS/2, 윈도 임베디드 콤팩트 그리고 윈도 NT 5.0 이상 기반 시스템의 명령어 인터프리터이다.라고라고 명시되어있는데  인터프리터와 컴파일러의 차이 같은 거 검색하시면 잘 나옵니다 구글에서 입니다.

경로(환경변수)를 설정한다는 의미는 미리 경로를 연결해두면 내가 원하는 폴더의 명령어 (ex node -v)를 어느 경로에서도 사용할 수 있음을 의미합니다. 

### **\-환경변수 설정하는 법**

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/3/img_2.webp)

제어판에서 찾아도 되고 위처럼 시스템 환경 변수를 검색해서 들어가도 좋습니다.

제어판으로 본다면 제어판-시스템-고급 시스템 설정으로 가주세요

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/3/img_3.webp)

이 창이 보일 텐데 환경 변수를 클릭합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/3/img_4.webp)

시스템 변수에서 Path라는 변수를 편집해주세요. 

새로 만들기를 클릭한 후 경로를 붙여 넣고 확인합니다. (ex C:\\Program Files\\nodejs\\node.exe)

위와 같이 경로를 입력한 후 확인을 모두 누르고 cmd의 초기 경로에서 node -v를 입력하셨을 때 버전이 잘 나온다면 환경변수 설정이 완료된 것입니다.

고생하셨습니다! 성실한 코딩 하세요.
