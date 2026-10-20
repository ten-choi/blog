---
title: "[ Architecture ] OOP와 SOLID를 이해하는 과정"
labels: ["Architecture","design_pattern","OOP","solid","DesignPattern"]
published: false
date: 2023-05-12T11:32:59+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 168
tistoryUrl: "https://yeolceo.tistory.com/168"
tistoryCategory: "Architecture/design_pattern"
tistoryTags: ["architecture","OOP","solid","KR","DesignPattern"]
tistoryPostedAt: "2023-05-12 11:32:59"
language: ko
bloggerPostId: "1311557868169956902"
---
### oop란 

object-oriented programming의 약어다  
말하자면 현실의 객체를 지향하는 개발 방식이다. 이게 어떤 말일까  
이해하기 쉽게 예시를 들어보자. 내가 차를 운전한다를 oop적으로 만들어보자

여기 사용되는 객체는 driver와 car가 존재한다  
car에는 handle, accelerator, break, engine, key, gearShift 등의 장치가 존재한다  
그럼 car는 각 장치 중 필요한 장치를 장착(상속)한다  
위처럼 객체들을 나누어 하나하나 명확히 정의하고 개발하는 방식이라고 보면 된다

특징과 원칙이 있다. 4가지 특징은 아래와 같다  
Encapsulation: 캡슐화  
Abstraction: 추상화  
Inheritance: 상속  
Polymorphism: 다형성

특징의 상세가 궁금한 사람들은 google을 찾아보자  
특징은 sourceCode를 작성할 때 active보단 passive라고 생각한다

### 원칙 5가지정리  

이건 active다. 실제로 사용하듯이 써야한단 말이다  
손은 많이가지만 다 적용되면 논리적으로는 좋다. 앞 글자를 따서 solid라고 부른다  
oop를 코드에 적용할때는 특징을 이해하고 원칙을 어기지 않는 것이 중요하다  
내가 정리한 link를 남긴다

-   SRP: [SRP](https://yeolceo.tistory.com/167)
-   OCP: [OCP](https://yeolceo.tistory.com/164)
-   LSP: [LSP](https://yeolceo.tistory.com/165)
-   ISP: [ISP](https://yeolceo.tistory.com/166)
-   DIP: [DIP](https://yeolceo.tistory.com/169)

특징은 머릿속에 넣고 원칙은 개발할 때 적용하자. 원칙을 몰라도 원칙대로 개발하는 사람도 꽤 많다  
문제는 크게 없을 수 있다 다만. 개발 관련 소통할 때 용어에 대한 이해가 필요할 수 있다고 생각한다
