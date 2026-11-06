---
title: "ERROR 1273 (HY000) at line 49: Unknown collation: 'utf8mb4_0900_ai_ci'"
labels: ["TroubleShooting","SQL","Unknown","mysql"]
published: true
date: 2021-11-22T13:50:42+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 111
tistoryUrl: "https://yeolceo.tistory.com/111"
tistoryCategory: "TroubleShooting/SQL"
tistoryTags: ["Unknown","mysql","mysql"]
tistoryPostedAt: "2021-11-22 13:50:42"
language: ko
bloggerPostId: "7137363029756788200"
---
## **Documentation**

상황  
sql을 dump 뜨고 복원하는 과정에서 위와 같은 에러가 발생했습니다

**1\. 문제 정의**

알 수 없는 방식의 데이터 수집(형식) utf8 mb4\_0900\_ai\_ci라고 합니다.

```html
ERROR 1273 (HY000) at line 49: Unknown collation: 'utf8mb4_0900_ai_ci'
```

**2\. 원인 규명**

외부 협업사 Linux Mysql 8.0에서 Local Window Mysql 8.0에 dump를 가져올 때 Charset이 달라서 문제일듯합니다.

**3\. 수정 및 테스트**

서치 후 dump 명령어 옵션에 'CHARSET=utf8 mb4'를 추가하여 테스트 진행하였습니다.  

```html
mysqldump -u xxxx  -h xxxx -p  --set-gtid-purged=OFF CHARSET=utf8mb4  xxxxdbname > C:/Users/xxxx/Dump2022xxxx.sql
```

**4\. 적용**

dump 파일이 잘 Import 되었습니다.

```html
Import of C:xxx/xxx/Dump20211122.sql has finished
```
