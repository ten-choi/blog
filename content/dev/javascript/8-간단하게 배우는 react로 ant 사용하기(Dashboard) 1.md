---
title: "간단하게 배우는 react로 ant 사용하기(Dashboard) 1"
labels: ["TS","JS","react","frontend","antdesign"]
published: false
date: 2020-05-25T15:02:08+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 8
tistoryUrl: "https://yeolceo.tistory.com/8"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","frontend","antdesign"]
tistoryPostedAt: "2020-05-25 15:02:08"
language: ko
bloggerPostId: "6871569175653977316"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/8/ant.webp)

**Ant Design 에 대해 검색하고 들어오셨다면 프론트엔드에 어느 정도 이해가 있으실 거라 생각합니다.**

(모르시겠다면 다음글부터 짚어가면서 설명하겠습니다!!)

간단히 설명드리자면 ant란 제품의 view를 쉽게 설계하기 위한 라이브러리를 사용하는 개념으로

bootstrap을 사용해보셨다면 유사한 사용방식입니다.

다만 앵귤러, 뷰, 리액트를 지원하는 라이브러리입니다. 

**사용 방법**

npm install -g react-create-app 로 리액트 앱을 만드는 npm을 인스톨 하셨다면

npx create-react-app 을 명령프롬프트에서 실행해주셔야합니다.  

**\- npx  npm의 차이점** 

    npm 은 아시다시피 노드의 패키지 매니져로서 필요한 모듈의 설치를 도와줍니다.

    다만 npm의 5.2버전부터는 npx라는 기본패키지를 제공합니다. npm은 모듈을 로컬폴더에 저장하고 실행합니다.

    하지만 글로벌 패키지와 로컬 패키지를 혼합해서 사용한다면 버전관리에 어려움을 겪을것입니다. 이를 해결하기위한

    npx로서 모듈을 저장하는것이아닌 최신버전을 불러와서 실행시킵니다. 즉 버전의 문제점을 보완한 npm의 툴입니다.

리액트 앱을 셋팅합니다.

후에 사용법은 아주 간단합니다.

[https://ant.design/](https://ant.design/)

url을 따라 접속한 후 components에 들어가면됩니다.  

그 후 본인이 원하는 View를 만들기 위한 태그를 왼쪽 사이드바에서 선택하면 됩니다.

[https://ant.design/components/layout/](https://ant.design/components/layout/)

예를 들어 layout을 들어간다면 레이아웃에 관한 이미지가 보입니다.

그 밑에 hide cods를 클릭한다면 어떻게 구성되어있는지에 대한 코드가 보일 것입니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/8/캡처.webp)

이렇게 원하는 모양을 가져다 사용하면 됩니다.

간단한 설명으로 적었습니다. 대부분의 코드에 대한 내용이 적혀있습니다만 영어이기 때문에 어려우시다면

크롬 한글 번역을 진행하시는 걸 추천드립니다.

**다음글은 ant를 이용해 간단한 버튼을 만들겠습니다.**
