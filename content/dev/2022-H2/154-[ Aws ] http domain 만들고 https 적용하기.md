---
title: "[ Aws ] http domain 만들고 https 적용하기"
labels: ["Cloud","route53","aws"]
published: true
date: 2022-12-29T13:13:13+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 154
tistoryUrl: "https://yeolceo.tistory.com/154"
tistoryCategory: "Cloud"
tistoryTags: ["route53","aws","aws","aws","aws"]
tistoryPostedAt: "2022-12-29 13:13:13"
language: ko
bloggerPostId: "9051975699470968638"
---
#### ? **환경** 

Aws platform

#### ? **개요**

aws에서 도메인 등록하고 https 적용하기

#### ? **목차**

-   what is the Route53
-   how to create
-   how to apply https

## **1\. What is the Route53** 

aws에서 제공하는 DNS(domain name service)입니다  
dns는 ip를 도메인으로 사용가능하게 하는 서비스입니다  
e.g) 0.0.0.0 -> test.co.kr

## **2\. How to create**

aws에서 route53을 검색합니다  
좌측 카테고리 상단에 호스팅 영역을 선택합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/154/img.webp)

호스팅에 사용될 이름을 생성합니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/154/img_1.webp)

도메인 이름을 작성하고 호스팅 영역을 생성합니다  
도메인 이름영역을 test.com으로 작성할 경우  
해당 영역에 생성하는 도메인은 ㅁㅁㅁㅁ. test.com으로 뒷부분 도메인이 통일됩니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/154/img_2.webp)

호스팅영역의 레코드를 생성해 줍니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/154/img_3.webp)

레코드도메인 뒤에 영역에서 설정한 도메인이 붙는 형태입니다  
제 경우에는 이미 존재하는 호스팅영역을 사용했습니다

이름을 작성하고 레코드 유형은 IPv4로 진행합니다  
별칭기능을 이용하여 Aws내의 라우팅할 서버를 지정합니다  

EB, EC2일 경우 라우팅대상과 리전을 알맞게 설정한 후 해당 도메인을 설정합니다  
CloudFront일 경우 라우팅대상과 리전을 알맞게 설정한 후  배포 도메인 이름을 넣어줍니다  
레코드 생성을 진행합니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/154/img_4.webp)

선택한 서버를 위에 작성한 도메인으로 접근이 가능합니다.

## **3\. How to apply https** 

https를 적용하고 싶다면 ssl 인증을 완료해야 합니다.   
aws에서 certificate manager를 검색합니다  
좌측상단의 나열 카테고리를 선택한 후 오른쪽 상단의 요청을 클릭합니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/154/img_5.webp)

호스팅영역에서 사용할 도메인과 동일하게 작성합니다  
만약 호스팅영역의 하위에 **서브도메인**을 만들고 싶다면 \*(asterisk)를 가장 앞에 붙여줍니다  
**서브도메인도 포함한 영역 사용법 e.g) \*. test.co.kr  
**그러면 route53에서 아래의 예시처럼 도메인을 작성해도 ssl이 적용됩니다   
****sub domain e.g) test1.test.co.kr**  
**

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/154/img_6.webp)

도메인 이름을 제외한 별다른 설정은 권장대로 가거나 따로 변경하지 않습니다  
생성이 완료되면 아래와 같이 상태에 검증 대기 중이 나옵니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/154/img_7.webp)

만들어진 인증서를 클릭합니다  
도메인에서 **Route53에서레코드생성** 버튼을 클릭합니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/154/img_8.webp)

CNAME유형의 레코드를 생성해 줍니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/154/img_9.webp)

이렇게 생성하면 route53에 CNAME을 가진 레코드가 생성됩니다  
해당레코드가 생성되면 얼마 지나지 않아 SSL인증이 완료됩니다

**? 근거 있는 조언은 언제나 환영합니다. 성실한 코딩 하세요.**
