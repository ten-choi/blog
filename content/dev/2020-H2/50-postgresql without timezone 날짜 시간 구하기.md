---
title: "postgresql without timezone 날짜 시간 구하기"
labels: ["DB","rdb","postgresql"]
published: true
date: 2020-09-25T16:45:31+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 50
tistoryUrl: "https://yeolceo.tistory.com/50"
tistoryCategory: "DB/rdb"
tistoryTags: ["postgresql","postgresql","postgresql"]
tistoryPostedAt: "2020-09-25 16:45:31"
language: ko
bloggerPostId: "5012682047065667821"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/50/img.webp)

## **\-짧고 간결하게 두문장만 보고 갑시다-**

select to\_char(now(), 'YYYY-MM-DD HH:MI:SS')                     딱 날짜와 시간만 ->소수점이나 timeznoe 없이 쓰는 법

select now()+'-5 minute' where now()+'-5 minute' > now()     오늘 기준으로 \[며칠, 몇 분, 몇 초\]  값만 불러올 때 

위 두문장만 있어도 postgresql 시간 관련은 대부분 해결 가능하게 됐네요.

도움받는 사람이 있길 바랍니다. 위에 방법 말고 더 나은 방법을 아신다면 언제든 지적 바랍니다. 

감사합니다.
