---
title: "[RPA UiPath 사용해보기] 2. Uipath 실행 테스트"
labels: ["ETC","RPA","UiPath"]
published: false
date: 2021-04-21T16:01:04+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 92
tistoryUrl: "https://yeolceo.tistory.com/92"
tistoryCategory: "ETC/RPA"
tistoryTags: ["UiPath","uipath","rpa","rpa"]
tistoryPostedAt: "2021-04-21 16:01:04"
language: ko
bloggerPostId: "2271410391276055489"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img-webp.webp)

### UiPath 실행 프로젝트

이번에 진행할 내용은 **UiPath**를 사용해 유저가 크롬에서 구글링 했던 행동을 **저장하여 실행**하는 부분까지

진행하려 합니다.

#### 1. 프로젝트 환경설정

새로운 프로젝트를 만들어줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img.webp)

프로젝트 명은 **googleSearch**로 진행하겠습니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_1.webp)

그리고 **Uipath**의 기능을 크롬 브라우저에서 사용할 예정입니다.

그렇게 하기 위해선 크롬에서 Uipath 확장 프로그램을 설치해주어야 합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_2.webp)

모든 크롬 사이트를 한번 종료해야 되니까 참고하고 진행해주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_3.webp)

설치가 **완료**되셨다면 아래와 같이 **모든 사이트에서 적용** 가능하게끔 설정해주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_4.webp)

만약 확장 프로그램을 설치하지 않았다면 아래와 같은 에러와 맞닥뜨렸을 겁니다!!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_5.webp)

자 이제 절반은 끝냈습니다. 거의 다 오셨습니다!

### 2. 간단한 프로젝트 구현

시작 카테고리로 가셔서 최근 생성 항목을 찾아봅시다! 저희가 앞서 만든 googleSearch를 클릭하여 실행해주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_6.webp)

드디어 프로젝트로 입성했습니다.

이번에 사용해볼 기능은 **상단 바에 있는 레코딩,** **파일 디버그** 이렇게 2가지가 있습니다.

****레코딩**버튼을** **클릭**해주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_7.webp)

데스크톱이나 웹을 클릭하셔서 진행해주세요. 데스크톱을 선택해도 가능은 하지만 웹 브라우저를

이용할 예정이니 웹을 선택해주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_8.webp)

그럼 아래와 같은 **레코딩** **창**이 나타납니다. 마우스를 올려보면 친절하게 설명도 나오니 참고해주세요.

(구글 초기화면을 띄워놓고 진행해주세요)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_9.webp)

**레코드 버튼**을 클릭하면 마우스가 변화합니다.  마우스를 입력 창에 올려놓고 **클릭**해주세요.

![](https://blog.kakaocdn.net/dn/msUXw/btq21MeojhC/uvXcWaM7N5oqMXo2kdMn0k/img.png)

그럼 아래와 같이 **원하는 값을 입력**하라고 나옵니다. 저는 한글로 **"검색"**이라고 입력한 후 **엔터**를 눌렀습니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_10.webp)

엔터까지 누르면 **입력 **레코딩**이** 완료된 것입니다.

다음 **레코딩**이 가능한 상태로 돌아오면 마우스를 밑으로 가져가서 **"Google 검색"**을 클릭해주세요

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_11.webp)

아래와 같은 화면으로 넘어갔다면 **저장 및 종료** 버튼을 누릅니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_12.webp)

새 시퀀스를 만들어 달라는 말이 나옵니다. **만들기를 클릭**해주세요. 제 경우 명칭은 기본값 그대로 사용했습니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_13.webp)

완료되면 uipath studio 화면에 **진행했던 프로세스**가 **플로우 차트**처럼 나타날 것입니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_14.webp)

이제 대망의 **실행**입니다. 여러분이 잘 따라와 주셨길 바라면서 **파일 디버그** 버튼을 눌러주세요!!

(구글 초기화면 띄워 둔 상태가 설정할 때와 동일해야 합니다.)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_15.webp)

저와 같이 시퀀스를 따라서 잘 진행이 되셨나요?

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_16.webp)

**RPA UiPath**에 기초적인 개념이 잡히셨나요? 그렇다면 축하드립니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_17.webp)

다음글을 만든다면 액티비티를 사용한 글을 올리려 합니다. 감사합니다.
