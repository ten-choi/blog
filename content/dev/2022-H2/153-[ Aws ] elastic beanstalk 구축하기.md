---
title: "[ Aws ] elastic beanstalk 구축하기"
labels: ["Cloud","elastic","AWS","eb"]
published: true
date: 2022-12-28T15:37:50+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 153
tistoryUrl: "https://yeolceo.tistory.com/153"
tistoryCategory: "Cloud"
tistoryTags: ["elastic","AWS","eb","aws"]
tistoryPostedAt: "2022-12-28 15:37:50"
language: ko
bloggerPostId: "276661303823342500"
---
#### ? **환경** 

Python 3.8  
Aws Plattform

#### ? **개요**

Aws에서 elastic beanstalk를 구축해 봅시다

#### ? **목차**

-   what is the eb
-   how to create eb

## **\- What is the eb**

Aws에서 제공하는 서버를 보다 쉽게 관리하기 위한 오케스트레이션 서비스가 eb(elastic beanstalk)입니다.   
주요 기능  
\- eb cli를 통한 배포설정 관리 및 신속한 배포  
\- 서버의 인프라, 로그, 모니터링, 용량 혹은 비용의 프로비저닝 등 관리 효율 증가

## **\- How to create eb**

aws내의 검색란에 eb를 검색합니다  
좌측 카테고리 상단의 애플리케이션목록을 클릭합니다  
우측 버튼으로 새 애플리케이션을 생성합니다  

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img.webp)

애플리케이션의 하위에 환경을 구성할 예정입니다  
생성할 프로젝트명과 eb 구성을 고려해서 이름을 작성합니다  
설명은 간단하게 적어줍니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_1.webp)

만들어진 애플리케이션에 새 환경을 생성합니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_2.webp)

웹서버 환경을 사용합니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_3.webp)

상위 애플리케이션 이름을 고려하여 하위환경이름을 작성합니다  
도메인에 특별히 의미를 부여할 경우 추가적으로 작성합니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_4.webp)

해당 블로그에서는 python의 django server를 기준으로 구성합니다  
따라서 플랫폼을 python으로 선택합니다  
개발 시 python 버전과 플랫폼 브랜치 python 버전 맞춰주는 것이 좋습니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_5.webp)

꼭! 추가 옵션 구성을 클릭해서 eb에 상세 설정을 해야 합니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_6.webp)

## **\- EB 추가 옵션 구성**

load balancing, auto scaling 등의 동작을 사용해주기 위해 단일 인스턴스는 지양합니다  
커스텀 가능한 사용자 지정 구성을 선택합니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_7.webp)

소프트웨어에서는 인스턴스에서 일어나는 상황을 로그로 남기는 설정을 합니다  
요금 적용이기 때문에 필요한 경우만 합니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_8.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_9.webp)

인스턴스에서는 보안그룹을 적용합니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_10.webp)

기본설정은 유지한 채로 보안 그룹만 따로 만들어서 사용했습니다  
[**보안그룹 만들기**](https://yeolceo.tistory.com/150)    
보안 그룹은 EC2 카테고리의 네트워크 및 보안에서 생성 가능합니다  
생성한 보안그룹을 선택해 줍니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_11.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_12.webp)

오토스케일링은 규모에 맞게 설정해줍니다 저는 2개 로진 행했습니다  
학습용으로 비용을 고려한다면 인스턴스는 1개로 세팅하면 됩니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_13.webp)

인스턴스사양은 **자세히 알아보기**로 성능 파악가능합니다  
저는 2 코어 2기가 메모리인 **t4g.small** 인스턴스로 진행했습니다  
[AwsEc2 사양링크](https://aws.amazon.com/ko/ec2/spot/instance-advisor/)  

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_14.webp)

조정 트리거에서는 환경의 상태를 알아볼 수 있습니다.  
CPU로 측정하고 단위는 %로 설정합니다  
상, 하위 임계값은 단위에 맞게 설정합니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_15.webp)

로드밸런스를 이용한 트래픽 분산 시 사용될 https 리스너가 필요합니다.  
ssl이 aws에 있을 경우 리스너에 추가해 줍니다.  
없을 경우 넘어갑니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_16.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_17.webp)

배포 전략인 블루그린, 롤링등 원하는 대로 배포방식을 설정할 수 있습니다  
저는 한 번에 배포로 진행했지만 배포 전략을 활용해보실 분들은 롤링과 비율을 고려하여 선택하면 됩니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_18.webp)

보안에서는 EC2 키페어를 만들어서 적용해 줍니다.  
[EC2키페어 만들기](https://yeolceo.tistory.com/152)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_19.webp)

이후 설정들은 따로 사용하지 않으므로 eb를 생성해 줍니다.

**? 근거 있는 조언은 언제나 환영합니다. 성실한 코딩 하세요.**
