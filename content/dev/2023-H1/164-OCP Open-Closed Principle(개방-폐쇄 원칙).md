---
title: "OCP: Open-Closed Principle(개방-폐쇄 원칙)"
labels: []
published: true
date: 2023-05-09T11:34:57+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 164
tistoryUrl: "https://yeolceo.tistory.com/164"
tistoryCategory: ""
tistoryTags: []
tistoryPostedAt: "2023-05-09 11:34:57"
language: ko
bloggerPostId: "2466086923899460926"
---
OCP: Open-Closed Principle(개방-폐쇄 원칙)

class나 module의 확장에는 열려있지만 수정에는 폐쇄적이라는 원칙이다  
말만 보면 뭔 소린가 싶다  
chatGPT를  사용해서 sampleCode를 만들어보자  
밑에 있는 첫 번째 sampleCode를 확인해 보자  

shape이라는 domain의 class가 있다  
그려야 하는 종류가 늘어날 때마다 shape class의 method는 늘어날 것이다  
그에 맞게 if 문도 계속 늘어날 것이다  
shape에서 그릴 수 있는 모양이 30개면 하나의 class에 30개의 유사한 method를 생성해야 한다 

```python
class Shape:
    def __init__(self, type, color):
        self.type = type
        self.color = color

    def draw(self):
        if self.type == "circle":
            self.draw_circle()
        elif self.type == "square":
            self.draw_square()
        elif self.type == "triangle":
            self.draw_triangle()

    def draw_circle(self):
        # 원 그리기 코드

    def draw_square(self):
        # 사각형 그리기 코드

    def draw_triangle(self):
        # 삼각형 그리기 코드
```

2번째 코드처럼 상속을 이용해 보자  
shape class는 draw가 추가될 때 내부코드가 변경될 필요가 없다  
그래고 확장할 때는 shape class를 상속받는 class에서 구현하면 된다  
if-elif 구문이 없어져 유지보수도 용이하다

```python
class Shape:
    def __init__(self, color):
        self.color = color

    def draw(self):
        pass

class Circle(Shape):
    def __init__(self, radius, color):
        super().__init__(color)
        self.radius = radius

    def draw(self):
        # 원 그리기 코드

class Square(Shape):
    def __init__(self, size, color):
        super().__init__(color)
        self.size = size

    def draw(self):
        # 사각형 그리기 코드

class Triangle(Shape):
    def __init__(self, base, height, color):
        super().__init__(color)
        self.base = base
        self.height = height

    def draw(self):
        # 삼각형 그리기 코드
```

딱 봐도 확장성과 가독성이 좋아졌다  
기초적인 개념이지만 기본을 신경 쓰자
