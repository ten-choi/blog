---
title: "ubuntu 18.04 한글 입력 간단하게 진행하기"
labels: ["OS","Linux","ubuntu"]
published: true
date: 2020-07-20T16:10:21+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 36
tistoryUrl: "https://yeolceo.tistory.com/36"
tistoryCategory: "OS/Linux"
tistoryTags: ["ubuntu","ubuntu","ubuntu"]
tistoryPostedAt: "2020-07-20 16:10:21"
language: ko
bloggerPostId: "4658618070456139267"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img.webp)

## \- 우분투 한글 타이핑 설정하기

자 이번에는 우분투에서 한글을 적용해보려 합니다.

우분투를 그냥 설치하기만 하면 한글은 적용되어있지 않습니다.

먼저 vmware환경에서 ubuntu를 실행해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_1.webp)

좌측 하단의 3X3 모양의 아이콘을 클릭합니다.

그러면 위와 같은 화면이 출력됩니다. 후에 language라고 쓰여있는 파일을 실행해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_2.webp)

본인이 설정한 ubuntu의 관리자 비밀번호를 입력해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_12.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_13.webp)

install language 버튼을 통해 korea를 선택하고 apply를 진행해줍니다. 위의 화면과 같이  
따라 하신 후 다운로드하시면 됩니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_3.webp)

저만 그런지는 모르겠지만 다운로드하는데 시간이 약 1시간 반 정도 걸렸습니다...

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_4.webp)

그냥 다운로드하면 되는 거지만 간혹 표시되지 않으시는 분들도 있다고 하시고 저도 그랬습니다.

한 번에 잘 뜨셨으면 바로 넘어가 주세요.  (안됬다면 다시 다운로드하시면 됩니다. 큰 다른 점은 없습니다.)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_5.webp)

터미널에서 다음과 같은 명령어를 입력해주세요 -> ibus-setup

그러면 다음과 같은 창이 하나 출력됩니다.

저는 이미 한글이 존재하지만 여러분은 추가가 안 돼있을 것입니다. add 버튼을 이용하여 korea를 찾아줍시다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_6.webp)

찾으셨다면 추가해줍니다. 이제 얼마 남지 않았습니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_7.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_8.webp)

설정이 끝났다면 한글 입력키로 바꿔주는 키 설정이 필요합니다.

왼쪽의 그림과 같은 이미지를 클릭하여 settings로 들어가 줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_9.webp)

위의 빨간펜으로 표시된 메뉴바를 따라가시면 위와 같은 설정창에 다다릅니다.

한글이 안 보인다면 추가해주기 위해 + 버튼을 선택하고 한글을 추가해줍니다.

그 후 별표 표시되어있는 설정을 클릭하여 아래와 같은 화면을 띄워줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_10.webp)

저 같은 경우에는 shift+space입니다. 여러분도 동일하시면 OK를 눌러 종료해주시고 아니라면 

본인이 원하는 지정키를 입력해주시면 됩니다.

축하드립니다! 이제 다 끝났습니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_11.webp)

터미널에서 해당 단축키를 사용하여 한글을 출력하였습니다. 지금까지 간단한 한글 출력하기였습니다. 

감사합니다.
