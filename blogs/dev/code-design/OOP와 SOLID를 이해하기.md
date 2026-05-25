---
title: "OOP와 SOLID 정리"
labels: ["architecture", "kr", "oop", "solid", "srp", "ocp", "lsp", "isp", "dip"]
date: 2023-05-11T19:32:00-07:00
bloggerPostId: "6864365946589347563"
published: true
originalUrl: "https://ten-logged.blogspot.com/2023/05/oop-solid.html"
---

## OOP란

oop란 object-oriented programming의 약어다  
말하자면 현실의 객체를 지향하는 개발 방식이다  
이게 어떤 말일까

이해하기 쉽게 예시를 들어보자  
내가 차를 운전한다를 oop적으로 만들어보자  
여기 사용되는 객체는 driver와 car가 존재한다  
car에는 handle, accelerator, break, engine, key, gearShift 등의 장치가 존재한다  
그럼 car는 각 장치 중 필요한 장치를 장착(상속)한다  

위처럼 객체들을 나누어 하나하나 명확히 정의하고 개발하는 방식이라고 보면 된다  

객체는 현실에서 책상, 의자 등의 사물을 객체라고 표현한다.  
의자와 책상에 대해 분석하고 개발에 적용해 보자는 논리다  
나는 적용하고싶지만 그냥 객체지향개발을 하세요 하면 모호하다  
정확하게 문제를 정의할 필요가있다  

## OOP의 4가지 특징

특징과 원칙이 있다  

4가지 특징은 아래와 같다  
Encapsulation: 캡슐화  
Abstraction: 추상화  
Inheritance: 상속  
Polymorphism: 다형성

특징의 상세가 궁금한 사람들은 google을 찾아보자  
특징은 sourceCode를 작성할 때 active보단 passive라고 생각한다

## SOLID 5원칙

원칙 5가지가 있다  
이건 active다. 다 적용되면 좋다  
앞 글자를 따서 solid라고 부른다

OOP에는 5개의 원칙이 존재한다  
5가지 원칙을 위배하지 않는 개발이면 OOP를 하고있다고 할수있다  
즉 OOP를 보지말고 5원칙을 만족해야한다  

oop를 코드에 적용하는 건 특징을 이해하고 원칙을 어기지 않는 것이 시작이라고 생각한다  

### SRP - Single Responsibility Principle (단일책임의 원칙)

class나 module은 하나의 책임을 가져야 한다고 한다

이해하기 쉽게 예시가 필요하다  
chatGPT를  사용해서 sampleCode를 만들어보자  
밑에 있는 첫 번째 sampleCode를 확인해 보자  

class Customer:
    def \_\_init\_\_(self, name, email, phone):
        self.name = name
        self.email = email
        self.phone = phone
    
    def place\_order(self, order\_items):
        \# 주문 정보 검증 및 처리
        pass
    
    def send\_email(self, subject, message):
        \# 이메일 전송
        pass

customer라는 domain에 다른 2가지 domain인 order, emailService가 들어가 있는 class다  
예를 들어 order 쪽이 고도화가 된다고 쳐본다  
order라는 domain에는 조회, 결제, 환불, 부분환불, validation, logging 등이 추가될 것이다  
  
order관련 sourceCode의 비율이 80%를 넘어간다고 가정하자  
그렇다면 customer class가 아니라 order class가 아닌가?  
주체가 모호해졌다  
class naming의 신뢰도가 떨어졌다  
  
고도화가 진행될수록 아래의 customer class는 거대해진다  
code 거다이맥스..  
확장성, 가독성이 떨어진다  

2번째 sourceCode를 봐보자

class Customer:
    def \_\_init\_\_(self, name, email, phone):
        self.name = name
        self.email = email
        self.phone = phone
    
class Order:
    def \_\_init\_\_(self, customer, order\_items):
        self.customer = customer
        self.order\_items = order\_items
    
    def validate\_order(self):
        \# 주문이 유효한지 검증하는 코드
        pass
    
    def process\_order(self):
        \# 주문을 처리하는 코드
        pass

class EmailService:
    def send\_email(self, customer, subject, message):
        \# 이메일 전송
        pass

domain별로 단일 책임이 들어갔다  
여기서 나온 domain은 customer, order, emailService 다

domain별로 잘 쪼개놓을수록 고도화가 진행될 경우 안정적인 개발이 가능할 것이다  
file structure는 해당 예시에서 고려하지 말도록 하자  
딱 봐도 확장성과 가독성이 좋아졌다

### OCP - Open-Closed Principle (개방-폐쇄 원칙)

class나 module의 확장에는 열려있지만 수정에는 폐쇄적이라는 원칙이다  
말만 보면 뭔 소린가 싶다

예시를 들어보자  
chatGPT를  사용해서 sampleCode를 만들어보자  
밑에 있는 첫 번째 sampleCode를 확인해 보자  

class Shape:
    def \_\_init\_\_(self, type, color):
        self.type = type
        self.color = color
    
    def draw(self):
        if self.type == "circle":
            self.draw\_circle()
        elif self.type == "square":
            self.draw\_square()
        elif self.type == "triangle":
            self.draw\_triangle()
    
    def draw\_circle(self):
        \# 원 그리기 코드
    
    def draw\_square(self):
        \# 사각형 그리기 코드
    
    def draw\_triangle(self):
        \# 삼각형 그리기 코드

shape이라는 domain의 class가 있다  
그려야 하는 종류가 늘어날 때마다 shape class의 method는 늘어날 것이다  
그에 맞게 if 문도 계속 늘어날 것이다  
shape에서 그릴 수 있는 모양이 30개면 하나의 class에 30개의 유사한 method를 생성해야 한다  
fu.. x..

2번째 코드처럼 상속을 이용해 보자  
shape class는 draw가 추가될 때 sourceCode가 변경될 필요가 없다  
확장할 때는 shape class를 상속받는 class에서 구현하면 된다

if-elif 구문이 없어져 유지보수도 용이하다  
딱 봐도 확장성과 가독성이 좋아졌다  

class Shape:
    def \_\_init\_\_(self, color):
        self.color = color
    
    def draw(self):
        pass

class Circle(Shape):
    def \_\_init\_\_(self, radius, color):
        super().\_\_init\_\_(color)
        self.radius = radius
    
    def draw(self):
        \# 원 그리기 코드

class Square(Shape):
    def \_\_init\_\_(self, size, color):
        super().\_\_init\_\_(color)
        self.size = size
    
    def draw(self):
        \# 사각형 그리기 코드

class Triangle(Shape):
    def \_\_init\_\_(self, base, height, color):
        super().\_\_init\_\_(color)
        self.base = base
        self.height = height
    
    def draw(self):
        \# 삼각형 그리기 코드

### LSP - Liskov Substitution Principle (리스코프 치환 원칙)

서브타입은 언제나 기반타입으로 교체 가능해야 한다는 원칙이다

기반타입이 상속해 주는 class고 서브타입이 상속받는 class에 느낌이다  
하위 class에서 실행한 동작을 상위 class에서 수행하면 동일한 동작을 해야 한다고 한다

chatGPT를  사용해서 sampleSourceCode로 이해를 쉽게 해 보자  
밑에 있는 첫 번째 sampleSourceCode를 확인해 보자

rectangle, square class가 있다  
square class에서 rectangle class를 상속받고 있다  
원칙대로 되려면 어느 class 던 같은 parameter를 넣었을 때 같은 결괏값이 나와야 한다

class Rectangle {
    protected int width;
    protected int height;

    public Rectangle(int width, int height) {
        this.width = width;
        this.height = height;
    }

    public void setWidth(int width) {
        this.width = width;
    }

    public void setHeight(int height) {
        this.height = height;
    }

    public int getArea() {
        return width \* height;
    }
}

class Square extends Rectangle {
    public Square(int size) {
        super(size, size);
    }

    public void setWidth(int width) {
        this.width = this.height = width;
    }

    public void setHeight(int height) {
        this.width = this.height = height;
    }
}

// Rectangle 객체와 Square 객체를 생성하여 각각 getArea() 메서드를 실행한 결과를 출력
Rectangle rectangle = new Rectangle(4, 5);
System.out.println(rectangle.getArea()); // 출력 결과: 20

Square square = new Square(5);
System.out.println(square.getArea()); // 출력 결과: 25

// Square 객체를 Rectangle 객체처럼 사용하려는 코드
Rectangle squareAsRectangle = new Square(5);
squareAsRectangle.setWidth(4);
squareAsRectangle.setHeight(5);
System.out.println(squareAsRectangle.getArea()); // 출력 결과: 25

마지막 결과를 보면 LSP에 위배된다  
LSP를 주장하는 이유 중 하나는 위배했을 경우 전혀 다른 결괏값이 나온다는 것이다

물론 설계에서 다른 결과의도를 가진 class에서 method형식이 동일하다는 이유로  
저렇게 개발하는 것이 문제긴 하다

첫 번째 sampleCode는 개발 시 square와 rectangle을 혼동시  
human error를 방지할 수 없다

2번째 코드를 봐보자  
공통적으로 사용할 getArea method가 존재한다  
코드를 아래처럼 재사용할 때 예상치 못한 결과를 방지할 수 있다는 점이 있다  
즉, 신뢰성이 올라가는 장점이 있다

interface Shape {
    int getArea();
}

class Rectangle implements Shape {
    protected int width;
    protected int height;

    public Rectangle(int width, int height) {
        this.width = width;
        this.height = height;
    }

    public void setWidth(int width) {
        this.width = width;
    }

    public void setHeight(int height) {
        this.height = height;
    }

    public int getArea() {
        return width \* height;
    }
}

class Square implements Shape {
    protected int size;

    public Square(int size) {
        this.size = size;
    }

    public void setSize(int size) {
        this.size = size;
    }

    public int getArea() {
        return size \* size;
    }
}

// Rectangle 객체와 Square 객체를 생성하여 각각 getArea() 메서드를 실행한 결과를 출력
Rectangle rectangle = new Rectangle(4, 5);
System.out.println(rectangle.getArea()); // 출력 결과: 20

### ISP - Interface Segregation Principle (인터페이스 분리 원칙)

client는 자신이 사용하지 않는 method에 의존하지 않아야 한다는 원착이다  
말이 너무 단순하다  
예시를 보면 이해하기 좋을 것 같다

chatGPT를  사용해서 sampleCode를 만들어보자  
밑에 있는 첫 번째 sampleCode를 확인해 보자

public interface Vehicle {
    void changeGear();
    void startEngine();
    void stopEngine();
    void accelerate();
    void brake();
    void turnLeft();
    void turnRight();
}

﻿ISP적용 없이 한 곳에 몰아넣은 interface를 봐보자  
저 interface를 사용하는 car class는 모든 기능을 사용해야 할 것이다  
하지만 car에 stick과 auto가 나뉘어있다면?  
그리고 changeGear가 stick 전용이라면?  
그리고 내차는 auto라면? holy... sh  
  
사용하지 않는 파츠를 차량에 구현해놔야 한다  
물리적으로 생각하면 훨씬 더 체감이 될 것이다  
내 자동차는 auto인데 동작하지 않는 장식용 1~5단 기어가 붙어있다는 소리다..  
  
결론적으로 불필요한 의존성과 결합도가 생긴다  
2번째 예시를 보자  
누가 봐도 interface 분리 원칙을 적용한 예시이다

public interface Gear {
    void change();
}

public interface Engine {
    void start();
    void stop();
}

public interface Acceleratable {
    void accelerate();
}

public interface Brakeable {
    void brake();
}

public interface Turnable {
    void turnLeft();
    void turnRight();
}

위처럼 interface를 분리하는 것만으로도 내차가 auto인 경우 Gear를 상속받지 않아도 된다  
즉 auto차량에서 gear를 조작하여 생길 문제의 가능성을 차단한다  
그리고 아래 car class처럼 사용한다  
  
ISP라는 이름에 걸맞은 분리였다

public class Car implements Engine, Acceleratable, Brakeable, Turnable {
    @Override
    public void start() {
        // 엔진을 시작하는 코드
    }

    @Override
    public void stop() {
        // 엔진을 멈추는 코드
    }

    @Override
    public void accelerate() {
        // 가속하는 코드
    }

    @Override
    public void brake() {
        // 브레이크를 밟는 코드
    }

    @Override
    public void turnLeft() {
        // 좌회전하는 코드
    }

    @Override
    public void turnRight() {
        // 우회전하는 코드
    }
}

### DIP - Dependency Inversion Principle (의존성 역전 원칙)

고차원 모듈은 저 차원 모듈에 의존해서는 안 되며, 추상화된 것은 구체적인 것에 의존해서는 안 된다는 원칙이다  
즉, 추상화된 인터페이스를 통해 두 모듈 모두 추상화에 의존해야 한다  
chatGPT의 설명이다.  

이게 뭔 말일까  
chatGPT를  사용해서 sampleCode를 만들어보자  
밑에 있는 첫 번째 sampleCode를 확인해 보자  

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

## 마치며

이렇게 살펴보면 이제 OOP를 하고있는지 여부를 판단할수있다

특징은 머릿속에 넣고 원칙은 개발할 때 적용하자  
원칙을 몰라도 원칙대로 개발하는 사람도 꽤 많다  
문제는 크게 없을 수 있다 다만  
개발 관련 소통할 때 용어에 대한 이해가 필요할 수 있다고 생각한다
