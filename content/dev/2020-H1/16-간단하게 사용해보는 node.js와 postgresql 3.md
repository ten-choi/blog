---
title: "간단하게 사용해보는 node.js와 postgresql 3"
labels: ["DB","rdb","PostgreSQL","node.js"]
published: true
date: 2020-06-05T15:31:03+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 16
tistoryUrl: "https://yeolceo.tistory.com/16"
tistoryCategory: "DB/rdb"
tistoryTags: ["PostgreSQL","node.js","postgresql"]
tistoryPostedAt: "2020-06-05 15:31:03"
language: ko
bloggerPostId: "5047958850908428118"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/16/img.webp)

2번째 게시글의 require 구문을 조금 수정하였습니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/16/img_1.webp)

최소한의 require로만 보여드리려 합니다.

설명에 없던 것 중 하나는 cors입니다. 이유는 서버에서 값을 넘겨줄 때 cors  에러가 뜨기 때문입니다.

외부에서 오는 데이터를 보안 목적으로 차단한다고 합니다. 그래서 라이브러리를 다운로드하여 해결합니다.

[npm cors](https://www.npmjs.com/package/cors)

그럼 추가할걸 다추가했습니다.

const config = {  
  user: '유저',  
  password:' 비번 ',  
  host: 'localhost',  
  port: 5432,  
  database: '디비명',  
};  
let pool = new Pool(config);

configure 환경 설정한다는 뜻입니다. db에 관련된 설정을 적어줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/16/img_2.webp)

바디 파서는 post 값을 받아주려고 씁니다. 

node.js에서만 구동하셨다면 bodyparser와 cors는 필요 없을 수 있습니다.

하지만 post 활용 및 db, server, client를 연동해줄 때 사용할 수 있으니 알아보시는 걸 추천합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/16/img_3.webp)

제가 만든 테이블 명은 usertable입니다. 유저네임만 불러줬습니다.

그리고 local포트의 3000번 포트  [http://localhost:3000/](http://localhost:3000/) 이곳에서 user를 추가해주신다면 불러주신 값이

node.js에서 출력될 것입니다.

순서대로 보자면 express 서버의 app을 get 방식으로 불러주는데 첫 번째 파라미의 경로로 불러줍니다.

밑에 db에 여태 넣었던 값을 토대로 연결을 해주는 connect를 해주고 첫 번째 파라미터

then값이 잘 통과 됐다면 query 문을 대입합니다.  쿼리 문도 잘 입력이 되면 연결을 종료하고

받아준 result 값을 send 해주면 내가 선택한 경로에 result.rows 열들의 값이 json타입으로 입력됩니다.

만약 다른 포트에 클라이언트 개념으로 페이지를 하나 더 만드셨다면 cors가 보안 문제를 해결해 줄것입니다.

감사합니다.
