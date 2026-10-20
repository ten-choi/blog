---
title: "node.js 의 koa 쉽게 사용하기"
labels: ["TS","JS","nodejs","KOA","koa.js"]
published: false
date: 2020-07-07T15:24:14+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 29
tistoryUrl: "https://yeolceo.tistory.com/29"
tistoryCategory: "TS, JS/nodejs"
tistoryTags: ["KOA","koa.js","node.js"]
tistoryPostedAt: "2020-07-07 15:24:14"
language: ko
bloggerPostId: "6402030765922790388"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/29/img.webp)

koa를 간단히 설명하자면 express와 같은 node.js에서 서버를 실행하기 위해 사용하는 웹 프레임워크입니다.

express의 개발자분들이 만드셨고 특징은 가벼움과 비동기 작업을 정식 지원하는 부분입니다.

써 내려가면서 설명하겠습니다. (큰 차이는 잘 느껴지지 않았습니다.)

## \- 초기 설정

yarn init -y를 실행하여 본인이 원하는 폴더에 파일을 생성합니다.

yarn add koa를 통해 해당 프레임워크를 다운로드합니다.

[https://www.npmjs.com/package/koa](https://www.npmjs.com/package/koa)

src폴더를 생성하고 index.js 파일을 폴더 내부에 생성합니다.

```html
const Koa = require('koa');

const app = new Koa();

app.use(ctx =>{              // ctx는 context의 줄임말로 웹의 요청과 응답의 정보를 지닌다.
  ctx.body='hello world';    //req와 res를 한번에 ctx로 사용한다고 생각하면된다.
});							// app.use((req,res)=>{}) 이게 익스프레스면 ctx는 하나로 쓴다.

app.listen(4000, ()=>{
  console.log('Listening to port 4000');
});
```

명령 프롬프트에서 본인의 폴더 경로에 node src를 실행해주세요.

localhost:4000를 주소창에 입력하고 엔터를 눌러주세요.

화면에 hello world 가 잘 나타난다면 기본이 끝났습니다.

## \- next함수 promise 반환

koa는 promise 형태의 반환이 가능합니다. 비동기 실행을 정식으로 지원하며 큰 특징입니다.

```html
const Koa = require('koa');
const app = new Koa();

 ///////////////////// 요부분이 비동기가 현재 일어나는 부분입니다.
app.use((ctx,next)=>{

  console.log(1);
  console.log(ctx.url);
  if(ctx.query.authorized !== '1'){
    ctx.status=401;
    return;
  }
  next().then(()=>{     //다음 next실행이 완료된 후에 end가 실행된다.
    console.log('END');
  });
});
////////////////////////////////
app.use((ctx,next)=>{
console.log(2);
next();
});

app.use(ctx =>{
  ctx.body = "hello world";
});

app.listen(4000, ()=>{
  console.log('Listening to port 4000');
});
```

로컬 4000의 query값을 비교할 때 값이 1이 아니면 status=401 설정을 하여 문서를 Unauthorized 상태로 표출합니다.

[http://localhost:4000/? authorized=1와](http://localhost:4000/?authorized=1) [http://localhost:4000의](http://localhost:4000/?authorized=1) 검색 결과를 보면 알 수 있습니다.

express에 대한 기반 지식이 있으시다면 이해가 용이할 것입니다.

 async와 await으로도 위의 비동기 처리가 가능합니다.

```html
위의 비동기부분 처리
app.use(async(ctx,next)=>{

  console.log(1);
  console.log(ctx.url);
  if(ctx.query.authorized !== '1'){
    ctx.status=401;
    return;
  }
    await next();
    console.log('END');
});
```

## \- koa router 사용하기 

[https://www.npmjs.com/package/koa-router](https://www.npmjs.com/package/koa-router)

yarn add koa-router를 사용하여 koa의 라우터를 추가합니다.

```html
const Koa = require('koa');
const Router = require ('koa-router'); //라우터 

const app = new Koa();
const router = new Router(); //라우터 설정

router.get('/', ctx =>{
  ctx.body= 'index페이지 (첫페이지)';
});

router.get('/blue', ctx =>{
  ctx.body= '파랑파랑';
});
router.get('/red', ctx =>{
  ctx.body= '빨강빨강';
});

app.use(router.routes());  //설정한 라우터들을 적용합니다.

app.listen(4000, ()=>{
  console.log('Listening to port 4000');
});
```

기본 페이지와 blue, red 페이지를 만들고 koa 서버를 실행합니다.

요렇게 모양이 잘 나오면 성공입니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/29/img_1.webp)

아주아주 간단한 웹에서의 router기능이 완성되었습니다.

모듈화를 진행해보겠습니다 이 또한 단순합니다.

코드부터 살펴보겠습니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/29/img_2.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/29/img_3.webp)

[12 행은 이렇게 해도 됩니다. app.use(router.routes());](http://app.use\(router.routes\(\)\);) 단 post나 get 같은 restApi 메서드를 사용할 때 적용이 안 된 경우

allowedMethods를 해줘야 에러가 안 뜨고 'allowedMethods' 문구가 출력됩니다.

\- rest api 란 요청 종류에 따라 다른 http의 메서드를 사용합니다. (하단의 restApi 종류)

\[   get : 데이터 조회 시 사용합니다. ㅣ post : 데이터 등록이나 인증 시 사용합니다. ㅣ delete :데이터를 지울 때 사용합니다.

             put : 데이터를 통째로 교환할 때 사용합니다.  ㅣ  patch : 데이터의 특정 필드를 수정할 때 사용합니다.   \]

현재 index페이지에 불러온 모듈 api.routes를 현재 router 추가합니다. 그러면 router에 api 모듈을 통한 경로도

사용 가능하고 후에 router의 routes를 이용해 express에도 use를 사용하여 적용해줍니다.

이렇게 하면 예를 들어 api경로를 통해 무수히 많은 경로가 있을 때 나눠놓는 것이 가능합니다.

이해하기 최대한 간편하게 koa의 기능을 살펴보았습니다. 도움이 되셨길 바랍니다.
