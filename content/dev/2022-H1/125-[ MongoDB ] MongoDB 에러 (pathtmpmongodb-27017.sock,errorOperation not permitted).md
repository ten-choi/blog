---
title: "[ MongoDB ] MongoDB 에러 (path\":\"/tmp/mongodb-27017.sock\",\"error\":\"Operation not permitted\")"
labels: ["TroubleShooting","mongoDB","Operation"]
published: true
date: 2022-02-17T12:38:25+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 125
tistoryUrl: "https://yeolceo.tistory.com/125"
tistoryCategory: "TroubleShooting"
tistoryTags: ["mongoDB","Operation"]
tistoryPostedAt: "2022-02-17 12:38:25"
language: ko
bloggerPostId: "621375691844301988"
---
#### 환경 

Aws  
RedHat 8  
MongoDB 4.4

#### 개요

RedHat에서 MongoDB 설치하고 실행할 때 나타나는 에러 관한 트러블 슈팅

## \- 해결법

sock 파일에서 권한 관련 문제가 생겼을 경우입니다. 그래서 mongod라는 유저의 권한을 혹시나 적용 안되었을 관련 파일, 폴더에 권한을 재설정해도 해결이 안 되었고 스택 오버플로우의 도움을 받아 해결하였습니다.

mongo 에러 로그  

```html
{"t":{"$date":"2022-02-10T00:44:16.121+00:00"},"s":"E",  "c":"NETWORK",  "id":23024,  
"ctx":"initandlisten","msg":"Failed to unlink socket file",
"attr":{"path":"/tmp/mongodb-27017.sock","error":"Operation not permitted"}}
```

## for Linux

```
$ sudo rm -rf /tmp/mongodb-27017.sock
$ sudo service mongod start
```

[https://stackoverflow.com/questions/63562177/mongod-aborts-on-mac](https://stackoverflow.com/questions/63562177/mongod-aborts-on-mac)
