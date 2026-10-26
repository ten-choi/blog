---
title: "초간단! python 설치하고 Atom으로 실행하기"
labels: ["Python","atom"]
published: false
date: 2020-10-21T17:18:46+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 55
tistoryUrl: "https://yeolceo.tistory.com/55"
tistoryCategory: "Python"
tistoryTags: ["python","atom","atom","python"]
tistoryPostedAt: "2020-10-21 17:18:46"
language: ko
bloggerPostId: "1172676210967289036"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img.webp)

파이썬 다운로드하고 atom도 다운로드해서 실행합니다. vscode를 원하시면 atom부분은 건너뛰어주세요.

## **\-파이썬 다운로드**

먼저 파이썬을 검색하여 공식 홈페이지의 **다운로드** 링크를 클릭합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_1.webp)

그러면 아래와 같은 화면이 나옵니다. 여기서 저희는 윈도 버전을 선택해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_2.webp)

보통 최신 버전은 공부할 때 쓰고 안정화가 돼있는 stable 버전을 실무 개발용으로 사용합니다.   
하지만 여기서는 Atom을 사용하기 위해서 **3.8**을 사용해야 합니다.   
제가 3.9를 써 본 결과 Atom의 **script Package**와 호환이 되지 않았습니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_3.webp)

스크롤을 내려서 위의 파란 라인의 인스톨을 진행해주세요.  Download -> Windows x86-64 executable installer

다운로드 파일이 생성되면 관리자 실행으로 실행해줍니다. 

체크 첫 번째 : 윈도의 모든 유저에게 파이썬을 설치한다.

체크 두번째 : 환경변수 path를 추가해준다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_4.webp)

화면에 3.9라고 뜨는 건 제가 3.9로 해봐서입니다... 3.8로 진행해주세요!!

하지만 실수로 진행하시는 분들도 커버 가능하게끔 최하단에 보완 가능한 수단을 적어놓았습니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_5.webp)

인스톨이 완료되었다면 윈도에서 idle이라고 검색하여 python을 실행해줍니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_6.webp)

바로 테스트 파이썬 해줍시다 1000 + 1000  이렇게만 해도 별다른 변수 없이 값이 잘 나와주는걸

 확인할 수 있습니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_7.webp)

## **\-아톰 다운로드**

이제  대망의 atom을 설치해줍니다. 이제 거의 다 왔습니다. 

[atom.io/](https://atom.io/)

다운로드하는 곳을 찾기 어려울 수 있습니다. 저어기 빨강.. 다운로드.. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_8.webp)

바로 아톰 실행하고 \[Ctrl\] + \[ , \]  왼쪽의 단축키로 세팅을 실행해줍니다.  

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_9.webp)

파이썬 코딩할 때 힌트를 주는 자동완성 기능입니다. 국 룰 패키지 다운로드해줍시다.  autocomplete-python 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_10.webp)

위에 거는 국 룰 패키지라면 아래 거는 없으면 실행 안됩니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_11.webp)

위의 다운로드 한 package는 atom에서 script 기능 지원하는 package입니다. 윈도껍니다.

아래에 있는 게 해당 패키지 문서의 단축키입니다. 껀뜨롤 시쁘뜨 비 해도 그냥 되던데

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_12.webp)

이제 거의 다 왔습니다. new file로 새로운 페이지를 생성해줍니다. 

그리고 아래와 같이 간단한 코드를 작성합니다.  print('print your code');

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_13.webp)

이제 Ctrl + s를 눌러주시면 어느 곳에 저장할지 창이 등장합니다. 저 같은 경우에는 바탕화면에

따로 test라는 폴더를 만들어 저장했습니다.  확장자는. py로 꼭 넣어주셔야 합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_14.webp)

이제 껀뜨롤 씨쁘뜨 비 

shift + ctrl + b 버튼을 이용하여 python을 실행해줍니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_15.webp)

아주 만약 저처럼 3.9 로한 애석한 분들이 계시다면 아래와 같은 경고가 뜰 것이며 해당 url을 클릭해주시면 됩니다.

Python was not found but can be installed from the Microsoft Store: [https://go.microsoft.com/fwlink?linkID=2082640](https://go.microsoft.com/fwlink?linkID=2082640)

결론은

3.9는 윈도에서 실행 가능하지만 atom의 script package 와는 아직 호환이 안 되는 것 같습니다.

아주 만약에 3.9를 다운로드하셨다면 위의 url을 이용하여 3.8을 다운로드해줍시다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_16.webp)

여러분은 실행들이 잘되셨나요?

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_17.webp)

Atom에서 Python 만들기였습니다. 성실한 코딩 하세요
