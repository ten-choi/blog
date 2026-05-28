---
title: "aws vpc 만드는법"
labels: ["aws vpc"]
date: 2023-06-15T21:55:00-07:00
bloggerPostId: "6380201699035551699"
published: true
originalUrl: "https://ten-logged.blogspot.com/2023/06/aws-vpc.html"
---
**Topic: how to create vpc on aws**

aws vpc란 virtualPrivateCloud의 약어다  
독립된 가상의 network공간을 제공하는 aws의 service다

이번에 vpc를 도입하는 이유는 nat 때문이다  
먼저 vpc의 구성도를 보면서 내부 instance와 외부의 data흐름을 파악해 보자

![](https://blog.kakaocdn.net/dn/bpNsJw/btsjJbakeKM/VOk3xhaww2rzwRBxnqTYEK/img.png)![](https://blog.kakaocdn.net/dn/cXL3PQ/btsj5wzyWiG/IKMSWqjFM8pDPQPlizyOt1/img.png)

from aws

만들어보면서 익히는 게 빠르다  
aws vpc를 만들어본다  
aws console에서 vpc를 찾아 생성버튼을 누른다  
아래와 같은 화면이 나오면 vpc 등을 선택한다  
"vpc만"으로 만드는 법은 글 하단에 따로 설명하겠다

![](https://blog.kakaocdn.net/dn/bNpHzd/btsj017CCtB/l5lgaDeXwpogGHUPEXTKo0/img.png)

az는 가용성을 높이기 위해 2개 이상을 권장한다  
2개의 az를 지정하여 az별로 private, public subnet를 1개씩 설정한다  
외부에 요청하는 ip를 하나로 통일하기 위해 nat를 설정한다

![](https://blog.kakaocdn.net/dn/cki0mT/btsj0aKvW8P/Qd7EOhNLtX2vRWUdFeItL1/img.png)

  
위와 같이 한 번에 만들면 vpc 설정은 끝이 난다  
내부 구조를 이해하기 위해 vpc 단일로 생성해 보자

ipv4 cidr에서 vpc에서 사용할 subnet 대역을 지정한다  
이외에는 기본설정을 유지하고 완료한다  
  

![](https://blog.kakaocdn.net/dn/el4kDG/btsj7b1UK2a/XxmrbHMcyE6xKxZMx7zEh0/img.png)

  

vpc에서 사용될 subnet을 만들어주자  
az(가용영역)는 a, b를 지정하여 2개를 만들어준다  
2개 이상이 고가용성을 위해 좋다고 한다  
public, private을 a, b의 영역에 1개씩 총 4개의 subnet을 만들어준다  
subnet에 넣을 ip규모에 따라 ipv4 cidr에 대역을 기입하자

![](https://blog.kakaocdn.net/dn/8D0zR/btsj5ZHTKOb/knPpt48dbefJembUjHp5qK/img.png)

  

해당 vpc에서 internet을 사용해야 한다  
igw를 만들어주고 해당 igw에서 작업 버튼을 눌러 vpc에 연결한다  
아래 이미지의 설명대로 vpc를 internet에 연결해 주는 가상 라우터다

![](https://blog.kakaocdn.net/dn/lU6vO/btsj54oIoEq/gZDHiNQ1lS6xBpfWEkUFsk/img.png)

  

자동에서는 라우팅 테이블을 3개 만들었다  
2개는 nat에 1개는 public subnet의 igw를 묶어줄 녀석이었다  
먼저 public subnet의 라우팅 테이블을 만들자

![](https://blog.kakaocdn.net/dn/KPR3y/btsj09Spy1m/pV9PMZAh7LwKmKxeUFFf10/img.png)

  

public subnet에서 igw를 통해 외부와 통신이 가능하게 설정하는 부분이다  
라우팅 편집을 통해 미리 생성했던 igw를 추가해 준다  
ip는 0.0.0.0 설정한다  
이유는 0.0.0.0은 해당 머신의 모든 ipv4 address를 의미한다  
그 말은 어느 host든 접근가능하게 연결해 주겠다는 의미다

서브넷연결 탭에서 public subnet 2개를 사용한다고 명시해 준다  
이제 public subnet은 internet은 외부에서 접근이 가능하다  

![](https://blog.kakaocdn.net/dn/kHlCe/btsj6Nz9ALk/0FZIRSxjaCGYKizkhND8SK/img.png)![](https://blog.kakaocdn.net/dn/d2W5cv/btsj3WrHBsN/YYzF9S4RquBfkKmfbYXsu0/img.png)

  

이제 private subnet을 사용할 라우팅 테이블 만들어야 하는데  
먼저 private subnet의 라우팅 테이블에서 igw역할을 할 nat를 만들어둬야 한다

nat는 vpc를 사용하는 큰 이유중하나다  
nat에서 eip를 하나 설정하면 외부에 요청하는 ip가 nat의 eip로 통일된다  
white list를 등록하는 회사가 있다면 하나의 ip로 내보내는 처리가 좋다

예를 들어 카카오의 어떤 server에 접근하는데 ip가 미리 등록돼 있는 것만 사용가능하다고 보자  
nat처리가 없다면 auto scaling을 통해 새로운 instance가 생기고 예상치 못한 ip가 생긴다  
등록된 ip가 아니라면 호출이 안되고 문제가 된다

nat는 public subnet에 위치한다  
그리고 private subnet에 있는 instance는  
라우팅 테이블을 통해 nat에 데이터를 보낼 수 있다  
그리고 nat를 통해 igw로 데이터를 내보내는 것이다

![](https://blog.kakaocdn.net/dn/duuqdh/btsj05vwsli/P2IMmDKRYrfKGGLIWXNqU1/img.png)

  

eip를 설정하고 연결 유형은 public으로 하고 완료하자  
이제 nat와 private subnet을 묶어줄 라우팅테이블을 만들어주면 된다

한 번에 만들기 기능에서는 private subnet의 경우  
라우팅 테이블을 2개 만든다  
아마 내부 통신용 라우팅 테이블과 외부통신용을 나누고 싶은 경우 등  
경우의 수에 따라 그렇게 하는듯하다

nat만 사용한다면 public subnet의 라우팅 테이블처럼 명시적 subnet에 2개를 설정해도 된다  
용도에 맞게 1개던 2개던 만들자  
igw가 있던 곳에 nat를 설정하고 subnet을 연결하면 된다 

![](https://blog.kakaocdn.net/dn/biGdKX/btsj07UCYrd/uvNgkUxRNUhVm9GTeZdZKK/img.png)

  

그렇게 하면 vpc의 설정은 끝이다
