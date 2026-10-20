---
title: "간단하게 배우는 react로 ant 사용하기(Dashboard) 4"
labels: ["TS","JS","react","frontend","antdesign"]
published: false
date: 2020-05-26T10:47:35+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 11
tistoryUrl: "https://yeolceo.tistory.com/11"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","frontend","antdesign"]
tistoryPostedAt: "2020-05-26 10:47:35"
language: ko
bloggerPostId: "7574206615211157201"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/ant.webp)

**이번에는 사이드 바를 제외한 layout 설정을 마무리 하겠습니다.**

layout 컴포넌트에 코드를 토대로 화면을 코딩합니다. 

레이아웃은 헤더(상단 메뉴)  , 사이더 (측면 메뉴)  컨텐츠( 중앙 내용) , 풋터 (하단에 설정할 내용)

으로 정리합니다.

**씬은 처음부터 나눠놓고 시작하는 것이 효율적입니다.**

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/1.webp)

스타일 설정은 사이더를 보시면 저런 식으로 색을 넣을 수 있습니다. red를 넣어줘서 구분을 줍니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/2.webp)

화면을 보시면 글자가 잘 안 보이시고 크기도 작습니다. 그러니 글자 크기를 변경하러 갑니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/3.webp)

타이틀을 이용할 건데 레벨이 크기를 의미합니다. 편하신 거 가져오셔서 헤더 사이에 넣을 겁니다. import는 꼭 해줍시다.

(from 'antd'가 겹치면 import { Layout , Typography} from 'antd'; 이런 방식이 보기 깔끔합니다.)

글씨가 잘 안보이 신다면 style을 토대로 color를 화이트로 바꿔주시면 타이틀명이 잘 보입니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/4.webp)

app.css에서 글의 중앙이 센터가 기준이라면 left로 바꿔줍시다. 대시보드는 보통 왼쪽 상단에 이름이 적혀있더라고요.

이제 user의 avatar를 설정할 것입니다.  우측 상단에 설정하여 로그인한 유저의 모습처럼 보일 것입니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/5.webp)

아바타의 모양을 가져옵니다. 경로를 src로 받아 이미지를 넣어주면 되는데 아바타에 넣을 이미지를

가지고 있지 않습니다. 그러니 아무거나 가져오셔도 되고 링크나 제가 올린 이미지를 참조하셔도 좋습니다. 

[https://icon-icons.com/](https://icon-icons.com/)

이런 곳에서 원하는 아이콘을 가져오셔도 좋고 제가 올린 아이콘을 사용하셔도 좋습니다.

이미지는 public폴더에 넣으셔야 합니다. (react에서 그렇게 이미지 src를 바로 가져옵니다. )

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/user-icon-test1.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/logo192.webp)

후에  제목 옆에 아이콘도 추가한다면 아래와 같은 코딩이 완료될 것입니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/3_1.webp)

위치가 안 맞으시면 패딩으로 간격을 조절하면 되고 텍스트는 이미 app.css 에서 left를 설정하였기에 float를 이용하여

Avatar의 위치를 설정해줍시다.  

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/2_1.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/blob.webp)

상단의 이미지가 이쁘게 나왔습니다. 하지만 아직 대시보드 같지는 않습니다.

중앙이 너무 별로입니다. 그러니 중앙을 채워주겠습니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/11.webp)

레이아웃으로 돌아가 컨탠츠 부분을 복사해옵니다.  스크롤바의 위치를 따라가서 </>를 클릭하시면 위와 같은 

코드가 나옵니다. 단 css를 설정해준 부분은 저 값을 그대로 div의 style로 직접 넣어주시길 바랍니다. 

import 잊으시면 안 됩니다.

Breadcrumb는 컨탠츠 위의 메뉴이고 그 안의 div는 중앙에 채울 내용의 위치를 표시합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/1_1.webp)

이 정도면 꽤 대시보드에 가까운 모습입니다. 여러분도 그러셨길 바랍니다. 현재 코드입니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/1_2.webp)

단시간에 이 정도 뷰를 구현할 수 있는 ant는 정말 굉장히 훌륭합니다. 

뷰에 할애할 시간을 단축시켜주는 무언가를 ant가 아니더라도 사용해 버릇하시면 도움이 됩니다.

다음 시간에는 사이드 바에 menu를 만들겠습니다. 감사합니다.
