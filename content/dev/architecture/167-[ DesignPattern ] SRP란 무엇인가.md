---
title: "[ DesignPattern ] SRP란 무엇인가"
labels: ["Architecture","design_pattern","OOP","solid","SRP","DesignPattern"]
published: false
date: 2023-05-11T16:13:24+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 167
tistoryUrl: "https://yeolceo.tistory.com/167"
tistoryCategory: "Architecture/design_pattern"
tistoryTags: ["architecture","OOP","solid","KR","SRP","DesignPattern"]
tistoryPostedAt: "2023-05-11 16:13:24"
language: ko
bloggerPostId: "2933601435494428310"
---
SRP: Single Responsibility Principle (단일책임의 원칙) class나 module은 하나의 책임을 가져야 한다는 말이다 이게 뭔소릴까 싶다

chat-gpt를  사용해서 sample code를 만들어보자  
밑에 있는 첫 번째 sample code를 확인해 보자

```ruby
class Customer:
    def __init__(self, name, email, phone):
        self.name = name
        self.email = email
        self.phone = phone

    def place_order(self, order_items):
        # 주문 정보 검증 및 처리
        pass

    def send_email(self, subject, message):
        # 이메일 전송
        pass
```

customer라는 주체에 다른 2가지 주체인 order, emailService가 들어가 있는 class다  
저런 code를 보면 벌써 불편하지만 조금 참기로 하자..  
예를 들어 order 쪽이 고도화가 된다 치자  
order라는 주체에는 조회, 결제, 환불, 부분환불, validation, logging 등이 추가될 것이다  

order 쪽 code의 비율이 80%를 넘어간다고 가정하자  
그렇다면 customer class가 아니라 order class가 아닌가  
주체가 모호해지면 class name도 신뢰도가 떨어진다  

그리고 고도화가 진행될수록 아래의 customer class는 정말 거대 해질 것이다  
아래의 class에서 code를 추가하며 확장하기도 별로고 다른 사람들이 읽기도 별로가 될 것이다

주체 별로 단일 책임을 주자  
여기서 나온 주체는 customer, order, emailService 다  
class 단위로만 나눠도 고도화가 진행될 경우 안정적인 개발이 가능할 것이다  
file structure는 해당 예시에서 고려하지 말도록 하자

```ruby
class Customer:
    def __init__(self, name, email, phone):
        self.name = name
        self.email = email
        self.phone = phone

class Order:
    def __init__(self, customer, order_items):
        self.customer = customer
        self.order_items = order_items

    def validate_order(self):
        # 주문이 유효한지 검증하는 코드
        pass

    def process_order(self):
        # 주문을 처리하는 코드
        pass

class EmailService:
    def send_email(self, customer, subject, message):
        # 이메일 전송
        pass
```

딱 봐도 확장성과 가독성이 좋아졌다  
기초적인 개념이지만 기본은 중요하다
