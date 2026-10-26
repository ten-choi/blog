---
title: "[ aws ] redis(elasticache) 만드는법"
labels: ["Cloud","aws","VPC","redis","ElastiCache"]
published: false
date: 2023-06-15T14:16:45+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 174
tistoryUrl: "https://yeolceo.tistory.com/174"
tistoryCategory: "Cloud/aws"
tistoryTags: ["KR","VPC","redis","ElastiCache"]
tistoryPostedAt: "2023-06-15 14:16:45"
language: ko
bloggerPostId: "6252446134136031094"
---
redis는 in-memory db다. aws에서는 elasticache로 명 칭이 돼있다  
elasticache를 aws console에서 검색하여 redis cluster를 생성해 보자

![](https://blog.kakaocdn.net/dn/v1nWH/btsj5wdZ16l/SoFMFQYdvF71UAaIKJjoqk/img.png)

기본설정 읽어보며 설정대로 진행한다. 일부 설정만 용도에 따라 변경하면 된다  
clusterMode는 성능을 얼마나 쓰느냐에 활성화 여부를 나눈다  
나는 refreshToken을 저장하는 용도로 redis를 사용할 예정이다  
그렇다면 고성능이 필요하지 않다. 비활성화하고 진행한다

노드 유형은 비용을 고려하여 선택한다. [awsRedis비용](https://aws.amazon.com/ko/elasticache/pricing/)  
vpc를 사용하는 경우의 예시를 추가한다  
server는 public, priavte 중에 private subnet의 instance에 존재할 것이다  
redis 또한 통신을 위해 private subnet을 선택하여 생성하자

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/174/img.webp)

보안그룹까지만 고려하여 선택하자  
이후는 대부분 기본설정에서 크게 벗어나지 않을 것이다
