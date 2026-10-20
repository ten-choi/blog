---
title: "[ aws ] eb관련 vpc설정 진행"
labels: ["Cloud","aws","eb","VPC"]
published: false
date: 2023-06-15T19:18:22+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 178
tistoryUrl: "https://yeolceo.tistory.com/178"
tistoryCategory: "Cloud/aws"
tistoryTags: ["KR","eb","VPC","aws"]
tistoryPostedAt: "2023-06-15 19:18:22"
language: ko
bloggerPostId: "688595466304122993"
---
aws에서 eb를 생성하자. 도입부는 최초의 설정 그대로 진행한다  
vpc 설정부에서 기존에 만들어놓은 vpc를 설정하자. 없다면 아래 img를 통해 flow를 이해하고  
link 한 문서를 참고하자-> [vpc 만들기](https://yeolceo.tistory.com/175)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/178/img.webp)

아래의 이미지에서 vpc에 private subnet 2개를 적용한다  
private이기 때문에 public ip는 비활성화한다  

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/178/img_1.webp)

security group이나 instance 유형은 상황에 맞게 적용하자  
기존 eb의 instance는 최소 2개의 사양이었다. loadBalencing 설정이 필요하다  
가시성은 public을 설정해 주자

eb의 alb에는 위에 vpc에서 사용하는 public subnet을 지정하자  
sample에서는 2개가 존재하며 2개다 지정한다  
route53 설정하면 dns를 거쳐 route53에서 alb에 요청을 넘겨줄 것이다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/178/img_2.webp)

이후 설정은 용도에 맞게 진행한다. 그리고 기존 project를 해당 eb에 배포한다  
정상적으로 동작하면 마무리가 된다  
외부 server에 redis와 filebeat 등이 존재한다면 vpc내부와 설정가능하게 연동하거나  
aws 내에서 만든다면 vpc의 private subnet에 맞춰 다시 만들어줘야 한다
