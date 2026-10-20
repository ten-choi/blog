---
title: "ERROR 1193 (HY000) at line 24: Unknown system variable 'GTID_PURGED' 및 dump 명령어"
labels: ["TroubleShooting","SQL","gtid_purged","Unknown","mysql"]
published: false
date: 2021-11-22T14:06:01+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 112
tistoryUrl: "https://yeolceo.tistory.com/112"
tistoryCategory: "TroubleShooting/SQL"
tistoryTags: ["gtid_purged","Unknown","mysql","mysql"]
tistoryPostedAt: "2021-11-22 14:06:01"
language: ko
bloggerPostId: "3147488123976934954"
---
## **Documentation**

상황  
sql을 dump 뜨고 복원하는 과정에서 위와 같은 에러가 발생했습니다

**1\. 문제 정의**

GTID\_PURGED가 알 수 없는 시스템 변수라 합니다. GTID란 Global Transaction Identifiers의 약자로 트랜잭션의 ID 값을 말합니다.

```html
ERROR 1193 (HY000) at line 24: Unknown system variable 'GTID_PURGED'
```

**2\. 원인 규명**

외부 협업사 Linux Mysql 8.0에서 Local Window Mysql 8.0 혹은 MariaDB의 10.3에 dump를 가져올 때 에러가 발생합니다. GTID를 지원하지 않는 버전에 dump를 복원하는 경우 생기는 에러일듯합니다.

**3\. 수정 및 테스트**

 첫 번째 방법 : 명령어로 dump를 할 때 --set-gtid-purged=OFF 부분을 추가해줍니다.

```html
mysqldump -u xxxx  -h xxxx -p  --set-gtid-purged=OFF  xxxxdbname > C:/Users/xxxx/Dump20211122.sql
```

 두 번째 방법 : 덤프 파일. txt에서 'SET @@GLOBAL.GTID\_PURGED' 이렇게 생긴 라인을 지워주시고 dump 복원을 하시면 됩니다. 

**4\. 적용**

두 가지다 GTID\_PURGED를 없애겠다는 문장이며 dump 파일 복원이 무사히 완료되었습니다.

```html
Import of C:xxx/xxx/Dump20211123.sql has finished
```

#오랜만에 검색했다가 추가 사항 등록 MySql 8.0 기준 -> 22.05.12  
저는 참고로 꺽쇠 방향 다른 거 까먹고 허튼짓을 한 시간을 함..

```bash
./mysqldump --set-gtid-purged=OFF -h 'localhost' -u root -p test-db > /Users/yeol/workspace/dump/DB_Backup.dump
./mysql -u root -p test-db < /Users/yeol/workspace/dump/DB_Backup.dump
```
