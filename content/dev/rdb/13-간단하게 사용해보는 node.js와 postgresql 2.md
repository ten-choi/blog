---
title: "간단하게 사용해보는 node.js와 postgresql 2"
labels: ["DB","rdb","PostgreSQL","node.js","react"]
published: false
date: 2020-05-26T16:36:57+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 13
tistoryUrl: "https://yeolceo.tistory.com/13"
tistoryCategory: "DB/rdb"
tistoryTags: ["PostgreSQL","node.js","node.js","react"]
tistoryPostedAt: "2020-05-26 16:36:57"
language: ko
bloggerPostId: "6759923018362356063"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/13/img.webp)

**cmd 명령 프롬프트를 먼저 실행합시다.**

원하는 폴더의 경로로 들어갑니다.  저의 폴더는 pg-test입니다.

npm init을 실행합니다. (node.js 가없다면 다운로드해야 합니다.) https://nodejs.org/ko/

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/13/img_1.webp)

package name은 통일성을 위해 pg-test로 했습니다. 

description은 설명에 대한 언급이므로 pg를 연습할 건데 티스토리에 올리기 위함이라 저렇게 설정했습니다.

author 저자는 쓰고 싶으면 쓰셔도 됩니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/13/img_2.webp)

전부 엔터를 누르면 완성됩니다.

이제 여러분의 폴더에는 package.json 파일이 존재할 것입니다. 저희는 아주 기본적인 틀을 완성하였습니다.

이제 의존성을 설정해줘야 합니다. 의존성이란 우리가 만들 폴더를 실행하기 위해 꼭 필요한 모듈들을 의존성이라 말하고

"dependencis"라고 합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/13/img_3.webp)

**이제 저희는 틀을 짰으니 어떤 환경을 가지고 실행할지 node에게 알려줍시다.** 

**자기가 뭘 쓰는지 아는 게 중요합니다.**

  "dependencies":{  
    "body-parser": "\*",  
       "dust": "\*",  
       "dustjs-helpers": "\*",  
       "dustjs-linkedin": "\*",  
       "express": "\*",  
       "pg": "\*",  
       "pg-pool": "^3.2.1",

       "consolidate": "\*"  
  }

**1 바디 파서란 post로 요청했을 때 요청 파라미터를 확인할 수 있도록  만든 미들웨어입니다.** 

//바디 파서를 이용해 넘어오는 코드를 파싱 합니다. 

app.use(bodyParser.urlencoded({extended:false });

url encoded라는 옵션인데 확장성의 값이 false면 node.js에 기본으로 있는 queryString을 사용하고 

true 값일 땐 npm qs 라이브러리를 사용한다는 뜻입니다.  queryString = URL 쿼리 문자열

전송에는 get방식과 post 방식을 주로 이용하는데 파라미터를 보낼 때 get과 post는 파싱 하는 방법이 다릅니다.

만약 클라이언트에서 post방식으로 submit(뭔가 데이터를 전송) 하면 

서버에서 requset를 할 때(받아줄 때) param방식으로 받아줄 수 있습니다.

클라이언트에서 <input name ={'id'} />로 값을 받아주고 post방식으로 submit 해준다면

서버에서는 let id = req.param('id'));    형태로 받아줄 수 있다는 뜻입니다.

**2 dust는 html을 보다 쉽게 쓰기 위한 템플릿입니다.  다른 dust종류도 템플릿을 위함입니다.**

**3\. express는 웹서버를 위해 만들어진 미들웨어로 HTTP모듈 위에서 동작합니다.** 

   쉽게 설명하면 node.js 에서 미들웨어로 쓰이며 서버 실행을 쉽게 하기 위한 프레임 워크입니다.

const express \= require("express");

const app \= express();

const PORT \= 3000;  

app.listen(PORT);  4줄만 있어도 서버는 실행됩니다.

**4\. pg와 pg-Pool  postgresql의 db를 사용하기 위한 모듈입니다.**

**5 consolidate는 템플릿을 통합하기 위한 라이브러리입니다. dust 템플릿을 사용하기 위함입니다.**

자 이제 저희가 무엇을 의존하고 있는지에 대해 이해하셨길 바랍니다. 그럼 이제 npm install을 통해 

의존한다고 명시한 모듈을 다운로드하도록 합니다.

app.js는 직접 만들었습니다. package 설정할 때 app.js를 main으로 한다고 설정해줬습니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/13/img_4.webp)

자 이제 기본 세팅을 해봅니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/13/img_5.webp)

express를 사용해서 웹서버를 구현하는데 포트번호 3000으로 설정하여 받아주겠다는 의미입니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/13/img_6.webp)

실행해보시면 콘솔 로그가 잘 찍힐 것입니다. [http://localhost:3000/](http://localhost:3000/) 를 실행하였을 때 Cannot GET / 에러가 뜬다면

성공적으로 서버를 만든 것입니다. 축하드립니다.

다음 글에서 postgresql을 사용하기 위한 방법을 알려드리겠습니다.
