---
title: "react 에서 express 로 값 전달하는 법 1"
labels: ["TS","JS","react","express"]
published: true
date: 2020-06-05T17:01:03+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 18
tistoryUrl: "https://yeolceo.tistory.com/18"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","react","express"]
tistoryPostedAt: "2020-06-05 17:01:03"
language: ko
bloggerPostId: "2401046973187607844"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/18/img_5.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/18/img_6.webp)

**이 글이 필요하신 분은 이미 react.js 와 node.js의 차이에 대해 아실 거라 믿고 진행하겠습니다.**

**1, 2 탄으로 정리해서 수정하였고 이전의 글에서 보완 완료했습니다! 3탄은 예정!**

**1은 node.js 2는 react 파트로 나뉩니다. node.js를 아신다면 아래 링크로 넘어가 주세요.**

[www.yeolceo.com/57](https://www.yeolceo.com/57)

**자 원하시는 부분 바로 들어가겠습니다! 먼저 node.js부터 시작하겠습니다.**

원하는 위치에 node.js 파일을 만들어줍니다.

저는 바탕화면에 폴더를 만들었습니다. 바탕화면-> server-> express  이경로에 말이죠

index.js라는 파일을 만들어주었습니다. (에디터는 아톰 사용 중입니다. VSCode가 더 유명합니다 유명한 거 쓰세요)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/18/img.webp)

해당 경로에 index.js 파일을 만들어주셨다면 아래와 같은 코드를 입력해줍니다.

node.js 에서 서버를 실행하기 위해 express를 사용한 간결한 코드 구문입니다.

```html
const express = require('express');  // express 라는 서버를 사용하기위한 프레임워크 받아오기
const app = express();        //express 사용
const port = 5050;            // 포트넘버 설정

app.get('/', (req, res)=>{                 //get 방식으로  '/' 경로를 사용할경우 send 표출
    res.send('안뇽 핼로우 월드 캬하하');
});

app.listen(port, ()=>{         // 서버 시작하는 부분
  console.log(`http://localhost:${port}  경로는 이거입니다.`);
})
```

자 이제 입력을 완료했다면 명령 프롬프트를 실행해주세요. 윈도에서 cmd를 검색하시면

명령 프롬프트가 실행됩니다. 그다음 본인이 설정한 경로로 이동해주세요. 아래는 예시입니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/18/img_1.webp)

#### 그리고 서버 사용을 도와주는 프레임워크 express를 설치해줍니다. 

  ( --save는 내가 express를 설치했다고 json이 존재할 때 저장하는 부분인데 생략하셔도 무방합니다!!)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/18/img_2.webp)

설치가 완료가 잘 되셨나요?  되었다면  node index.js를 명령 프롬프트에 입력하고 엔터 해줍니다.

실행이 됐나요~?

그렇다면!! 인터넷 화면에서 로컬 호스트를 통해 5050 포트->  http://localhost:5050/  로 접속해줍시다. 

접속하면 아래와 같이 잘 뜨셨다면 잘 따라와 주신 겁니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/18/img_3.webp)

고롷다면 이제 node.js 는 기본 세팅이 완료되었습니다. 아주 잘하셨습니다!

이제 일부 기능을 조금 더 추가해주겠습니다. 

npm i body-parser를 진행해주세요.  post 형태로 값을 넘겨받을 때 parser가 있어야 온전히 값을 받을 수 있습니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/18/img_4.webp)

npm을 보면 더 자세한 설명이 영어로.. 적혀있어요.

[www.npmjs.com/package/body-parser](http://www.npmjs.com/package/body-parser)

아주 잘 따라와 주신 여러분 모두 잘하셨습니다. 

#### **body-parser를 추가하여 저희의 코드를 완성해볼까요?**

```html
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const port = 5050;

app.use(bodyParser.json());

app.post('/api', (req, res)=>{
  let name = req.body.name;
    console.log(name);
    console.log('탐정이죠 ');
});

app.listen(port, ()=>{
  console.log(`http://localhost:${port}  경로는 이거입니다.`);
})
```

name으로 어떤 값을 받아올지는 예측 가능하다고 생각합니다!! ㅋㅋ

node.js 부분은 이렇게 아주 간단히 마무리가 되었습니다.  react를 수정을 바로 가시기 전에 위의 코드가

잘 이해가 되는지 확인하고 넘어가면 더 좋습니다!!

완료되셨다면 아래의 링크로 넘어가 주세요!

[www.yeolceo.com/57](https://www.yeolceo.com/57)
