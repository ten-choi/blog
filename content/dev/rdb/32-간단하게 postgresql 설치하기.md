---
title: "간단하게 postgresql 설치하기"
labels: ["DB","rdb","PostgreSQL"]
published: false
date: 2020-07-16T13:33:00+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 32
tistoryUrl: "https://yeolceo.tistory.com/32"
tistoryCategory: "DB/rdb"
tistoryTags: ["PostgreSQL","postgresql","postgresql"]
tistoryPostedAt: "2020-07-16 13:33:00"
language: ko
bloggerPostId: "7619077862800503198"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/32/img.webp)

## \- postgresql 이란

관계형 데이터 베이스의 일종입니다. 제가 사용하는 이유는 postgresql로 하라고 해서입니다. 일반적인 RDB는 sql문으로 관리하기 때문에 db는 선택입니다. 

## \- postgresql 설치 파일 다운로드

postgresql 사이트에 접속하여 설치하면 됩니다. 하단의 링크를 남겼고 저는 하단의 표시한 부분을 클릭

다운로드하였습니다. (64비트입니다.)  11을 택한 이유는 최신보단 안정적인 하나 아래 버전을

선택했습니다. 원하시면 12 하셔도 무방합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/32/img_1.webp)

[https://www.enterprisedb.com/downloads/postgres-postgresql-downloads](https://www.enterprisedb.com/downloads/postgres-postgresql-downloads)

## \- postgresql 진행과정

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/32/img_2.webp)

installer 가 시작됩니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/32/img_3.webp)

postgresql 서버 및 관리 툴입니다.

스택 빌더는 postgresql을 보완하는 도구나 드라이버, 앱 등을 설치하는데 이용되지만 저는 사용하지 않습니다. 

체크를 해제해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/32/img_4.webp)

파티션이 구분되어있으신분들은 원하는 경로로 변경해주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/32/img_5.webp)

\*text파일을 만들어서 꼭 비밀번호는 따로 저장해두는 것을 추천합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/32/img_6.webp)

postgresql 은 기본적으로 포트 5432를 주로 사용합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/32/img_7.webp)

로컬을 사용합니다. 특별한 옵션을 사용할 이유가없습니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/32/img_8.webp)

다운로드가 완료될 때까지 기다려줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/32/img_9.webp)

스택 빌더 체크를 해제하고 완료 버튼을 클릭합니다.

축하드립니다. 너무 쉬운 postgresql 설치가 완료됐습니다.

설치가 다되었으면 실행으로 옮겨봅시다.

[https://yeolceo.tistory.com/7?category=919564](https://yeolceo.tistory.com/7?category=919564)
