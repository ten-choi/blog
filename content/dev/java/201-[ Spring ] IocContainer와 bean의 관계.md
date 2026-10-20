---
title: "[ Spring ] IocContainer와 bean의 관계"
labels: ["Java","Kotlin","spring","DI","bean","IoCContainer"]
published: false
date: 2023-12-07T19:39:04+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 201
tistoryUrl: "https://yeolceo.tistory.com/201"
tistoryCategory: "Java, Kotlin/spring"
tistoryTags: ["Java","Spring","DI","bean","KR","IoCContainer"]
tistoryPostedAt: "2023-12-07 19:39:04"
language: ko
bloggerPostId: "6748122215786148123"
---
## **Bean이란**

springContainer에서 관리되는 재사용가능한 자바객체를 말합니다

이는 class의 instance화 된 객체를 의미합니다. spring의 annotation를 통해 메서드로부터 반환된 객체를 springContainer에 등록합니다 bean은 class의 등록정보와 함께 getter/setter 메서드를 포함하여 컨테이너에 사용됩니다

실제 코드에서는 bean에 직접 접근하는것이 아닌 spring이 제공하는 getBean() 메서드를 통해 간접적으로 접근합니다IocContainer가 bean을 관리하고 애플리케이션에 필요한 객체를 제어하는 구조를 유지합니다.

## **IocContainer란**

제어의 역전(IoC)은 소프트웨어 엔지니어링의 핵심 개념 중 하나로, 프로그램의 제어를 전적으로 다른 시스템이나 프레임워크에 위임하는 것입니다. IoC 컨테이너는 이러한 개념을 실현하는데, 이는 객체의 생명주기와 의존성 주입을 관리하여 애플리케이션의 제어를 가져가는 역할을 합니다.  

스프링 프레임워크에서 IoC 컨테이너는 ApplicationContext로 명명되며, 이를 스프링 컨테이너 또는 DI(Dependency Injection) 컨테이너로도 불립니다. 이 컨테이너는 객체(빈)의 생성, 의존성 주입, 관리 및 폐기 등을 담당하며, 이는 코드가 아닌 컨테이너의 권한으로 이루어집니다.  

이는 객체의 생명주기와 관련된 작업을 직접 코드에서 다루는 대신 스프링 컨테이너가 담당하여 제어의 주도권이 역전된 것을 의미합니다. 따라서 스프링 컨테이너를 IoC 컨테이너라고도 부릅니다.  

## **DI란**

의존성

의존성 주입은 프로그램 디자인 결합도를 느슨하게 되도록 하고, 의존관계 역전 원칙과 단일 책임 원칙을 따르도록 클라언트의 생성에 대한 의존성을 클라이언트의 행위로부터 분리하는 것이다.
