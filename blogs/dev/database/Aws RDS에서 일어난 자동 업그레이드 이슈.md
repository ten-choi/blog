---
title: "Aws RDS에서 일어난 자동 업그레이드 이슈"
labels: ["aws rds", "trouble shooting"]
date: 2023-06-01T21:49:00-07:00
bloggerPostId: "3221506798590588833"
published: true
originalUrl: "https://ten-logged.blogspot.com/2023/06/aws-rds.html"
---
**Topic: Troubleshooting for Amazon RDS auto minor update**

aws rds 사용 도중에 issue가 발생했다  
문서화를 진행해 보자

1\. 문제정의  
server에서 아래와 같은 error가 등장한다

Cannot execute statement in a READ ONLY transaction.
Error: Cannot execute statement in a READ ONLY transaction.

2\. 원인규명  
aws rds의 setting 중에 "마이너 버전 자동 업그레이드 사용" 설정이 체크되어 있었다  
upgrade scheduler에 시간을 보니까 에러가 시작된 시간과 일치한다  

rds cluster의 spec은 instance가 총 3개이고  
write 1개 read 2개이다  
  
예상 시나리오는 아래와 같다  
설정된 시간에 rds cluster 전체에서 각 instance 별 update를 진행  
write db에서 memory 부족으로 error 발생했다는 로그가 확인  
write instance가 reboot 되면서 write 할 수 있는 instance가 없음  
read instance에 write 역할을 부여  
재시작한 instance는 read의 역할을 부여하여 비율을 맞춘다  
이때 server에서 db를 호출하는 endPoint가 문제가 있었다  
rds cluster의 write endPoint가 아닌 instance의 endPoint를 사용 중이었다  
역할이 바뀌어도 cluster의 write, read endPoint를 사용하면 문제가 없다  
알아서 구분해 주기 때문이다  
하지만 instance의 endPoint를 사용했다  
그리고 재시작한 instance는 read의 역할이다  
그러면 server에서는 write 하기 위해 호출하는 instance가 read의 endPoint를 이용하는 경우가 생긴다  
그래서 위와 같은 에러가 나오게 되었다

3\. 수정 및 검수  
cluster에 지정되어 있는 write endPoint를 사용하도록 변경했다  
read는 cluster 거로 잘되어있었다  
이게 정석인데 write 쪽 endPoint는 이전에 잘못되어 있었나 보다  
lb도 cluster에서 역할별로 자동으로 해주는 듯하다

server는 elb사용 중이다  
해당 elb의 env에 write instacne endPoint를 cluster의 endPoint로 변경한다  

4\. 배포  
env에 환경 변수를 바꾸고 저장한다  
그러면 server instance가 알아서 재시작하며 적용된다
