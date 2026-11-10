---
title: "Topic: What is the DIP"
labels: []
published: true
date: 2023-05-12T14:20:49+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 169
tistoryUrl: "https://yeolceo.tistory.com/169"
tistoryCategory: ""
tistoryTags: []
tistoryPostedAt: "2023-05-12 14:20:49"
language: ko
bloggerPostId: "492857020996402371"
---
#### **Topic: What is the DIP**  

DIP:Dependency Inversion Principle(의존성 역전 원칙)  
고차원 모듈은 저 차원 모듈에 의존해서는 안 되며, 추상화된 것은 구체적인 것에 의존해서는 안 된다는 원칙이다  
즉, 추상화된 인터페이스를 통해 두 모듈 모두 추상화에 의존해야 한다  
chatGPT의 설명이다.

이게 뭔 말일까  
chatGPT를  사용해서 sampleCode를 만들어보자  
밑에 있는 첫 번째 sampleCode를 확인해 보자

```java
public class OrderProcessor {
    private EmailSender emailSender = new EmailSender();

    public void processOrder(Order order) {
        // 주문 처리 로직
        emailSender.sendEmail("주문이 접수되었습니다.", order.getCustomerEmail());
    }
}

public class EmailSender {
    public void sendEmail(String message, String recipientEmail) {
        // 이메일 발송 로직
    }
}
```

위의 코드를 보자  
order method를 사용하면 무조건 order는 email로 해야 한다  
sourceCode가 그렇게 돼있다

만약 email이 아니라 다른 매체로 발송하고 싶다면?  
order method로직을 수정하고 다른 매체 class도 추가해야 할 것이다  
즉, 저 차원 module인 send 동작이 추가되는데 고차원 module인 order가 변경된다는 소리다

2번째 코드예시처럼 interface를 이용해 보자  
email과 sms를 보내는 class가 있다

interface를 통하기 때문에 order class는 수정하지 않아도 된다  
새로운 기능을 추가할 때는 새로 class를 구현하고 interface를 상속(inheritance)하면 된다  
decoupling 되고 확장성이 올라간다

```java
public class OrderProcessor {
    private IMessageSender messageSender;

    public OrderProcessor(IMessageSender messageSender) {
        this.messageSender = messageSender;
    }

    public void processOrder(Order order) {
        // 주문 처리 로직
        messageSender.sendMessage("주문이 접수되었습니다.", order.getCustomerEmail());
    }
}

public interface IMessageSender {
    void sendMessage(String message, String recipientEmail);
}

public class EmailSender implements IMessageSender {
    public void sendMessage(String message, String recipientEmail) {
        // 이메일 발송 로직
    }
}

public class SMSSender implements IMessageSender {
    public void sendMessage(String message, String recipientEmail) {
        // SMS 발송 로직
    }
}
```
