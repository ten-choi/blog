---
title: "간단하게 사용해보는 node.js와 postgresql 1"
labels: ["DB","rdb","PostgreSQL"]
published: true
date: 2020-05-22T17:32:01+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 7
tistoryUrl: "https://yeolceo.tistory.com/7"
tistoryCategory: "DB/rdb"
tistoryTags: ["PostgreSQL","postgresql","postgresql"]
tistoryPostedAt: "2020-05-22 17:32:01"
language: ko
bloggerPostId: "3675706724764352080"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/7/img.webp)

postgresql 아주 간단히 설명하자면 예전에 나온 RDB입니다.

RDB와 nosql의 차이는 모르신다면 구글링으로 개념 잡으시는 걸 추천합니다. 

개인적으로 mysql oracle 의 차이를 느끼지 못했습니다.

(깊은 이해가 필요없이 그냥 db로서 사용했습니다. 전 그렇더라고요. )

db를 개인적으로 개발할 때 쓰기보단 외부 프로젝트에서 쓰지 싶네요. 

[https://www.enterprisedb.com/downloads/postgres-postgresql-downloads](https://www.enterprisedb.com/downloads/postgres-postgresql-downloads)

링크입니다. 여기서 윈도우용 64비트 다운로드하시면 됩니다. 

stack 빌더는 제외하고 다운로드하으셔도 무방합니다. 저는 쓸 일이 없었습니다.

다운로드중에 입력하는 주요 정보들은 따로 text파일로 저장하시는걸 추천합니다. 

(ex   pgReadMe.txt  ->   password : asdf       port : 5432) 필요해 보이면 다 따로 텍스트에 적어놓는게 좋습니다. 

적어두는 습관은 도움이 됩니다. 

전부 다운로드한 후 윈도우 검색창에서 pgadmin 검색하시면 실행파일이 보이실겁니다.

**자 이제 윈도우에서 pgadmin을 검색해봅시다.**

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/7/img_1.webp)

여기서 pgadmin 을 검색하시면 됩니다. 간단하죠.

나온 실행파일을 클릭합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/7/img_2.webp)

이런 화면이 웹에서 등장합니다.  앞서 글을 보고 오셨으면 text로 저장해놓은 비밀번호를 입력하시면 됩니다.

보통 그냥 자기 편한 비번을 미리 적으셨을테니 설치때 적으신 비번 적으시면 됩니다. 

(아주아주 만약에 본인이 컴퓨터를 잘관리하는사람이라면 pg의 sql서비스를 종료해놓는경우가있습니다.  
 램먹지말라구요. 근데 종료해두면 db가 안켜지니까 이부분 참고하세요. 전 관리를 잘해서 서비스 종료해놨었거)

**아주 간단하게 실행 되었습니다.** 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/7/img_3.webp)

리스트를 나온대로 클릭하시면 저와 같은 화면이 나올 것입니다.

데이터 베이스, 스키마, 테이블은 우클릭 create만 쓰셔도 만드실 수 있습니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/7/img_4.webp)

아주 간단하게 이름만 설정하시고 save 하면 테이블 완성입니다.

table에서 우클릭을 하면 당연히 칼럼도 만들 수 있습니다.  너무 간단합니다.

우클릭 최하단에 sql문 query tool 이 있으니 원하시면 직접 만드셔도 됩니다!

정말 간단하게 postgresql의 사용법이 끝났습니다.   이게 전부입니다. 

다음 포스팅할 내용은 node.js 와의 연동입니다. 

저는 atom에디터로 node.js 환경에서 postgresql을 사용할 것입니다.
