---
title: "[ TroubleShooting ] Aws RDS 자동 업데이트로 인한 문제 발생"
labels: ["TroubleShooting","Aws","RDS"]
published: false
date: 2023-06-02T13:50:00+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 173
tistoryUrl: "https://yeolceo.tistory.com/173"
tistoryCategory: "TroubleShooting/Aws"
tistoryTags: ["TroubleShooting","KR","aws","RDS"]
tistoryPostedAt: "2023-06-02 13:50:00"
language: ko
bloggerPostId: "5852300009282878604"
---
aws rds 사용 도중에 issue가 발생했다  
문서화를 진행해 보자

1\. 문제정의  
server에서 아래와 같은 error가 등장한다

```smali
Cannot execute statement in a READ ONLY transaction.
Error: Cannot execute statement in a READ ONLY transaction.
```

2\. 원인규명  
aws rds의 setting 중에 "Automatic Minor Version Upgrades" 설정이 체크되어 있었다  
upgrade scheduler에 시간을 보니까 에러가 시작된 시간과 일치한다  
rds cluster의 spec은 instance가 총 3개이고 write 1개 read 2개이다

예상 시나리오는 아래와 같다  
설정된 시간에 rds cluster 전체에서 각 instance 별 update를 진행되었다  
write db에서 memory 부족으로 error 발생했다는 로그가 확인했다  
write instance가 reboot 되면서 write 할 수 있는 instance가 없고  
자체적으로 read instance에 write 역할을 부여하게 될 것이다  
재시작한 instance는 read의 역할을 부여하여 비율을 맞추게 된다  
이때 server에서 db를 호출하는 endPoint가 문제가 있었다  
rds를 사용하는 server에서 rds cluster의 write endPoint가 아닌 instance의 endPoint를 사용 중이었다  
역할이 바뀌어도 cluster의 write, read endPoint를 사용하면 문제가 없다 알아서 구분해 주기 때문이다

하지만 instance의 endPoint를 사용했다  
그리고 재시작한 instance는 read의 역할이다  
그러면 server에서는 write 하기 위해 호출하는 instance가 read의 endPoint를 이용하는 경우가 생긴다  
그럼 권한이 없고 위와 같은 에러가 나오게 된다

3\. 수정 및 검수  
cluster에 지정되어 있는 write endPoint를 사용하도록 변경했다  
read는 cluster의 endPoint로 잘되어 있었다  
이게 정석인데 write 쪽 endPoint는 누군가 초기설정을 잘못한듯하다  
load balancer역할도 cluster에서 역할별로 해주는 듯하다

server는 aws의 eb를 사용 중이다  
eb의 env에 write instacne endPoint를 cluster의 endPoint로 변경하자

4\. 배포  
env에 환경 변수를 바꾸고 저장한다  
그러면 server instance가 알아서 재시작하며 적용된다
