---
title: "OCP: The Open-Closed Principle"
labels: ["Archive"]
published: true
date: 2023-05-09T11:34:57+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 164
tistoryUrl: "https://yeolceo.tistory.com/164"
tistoryCategory: ""
tistoryTags: []
tistoryPostedAt: "2023-05-09 11:34:57"
language: en
bloggerPostId: "2466086923899460926"
---
OCP: Open-Closed Principle

It's the principle that classes and modules should be open for extension but closed for modification.  
Reading that alone, you might wonder what it even means.  
Let's use ChatGPT to make some sample code.  
Take a look at the first sample below.  

There's a class for the shape domain.  
Every time a new kind of shape needs to be drawn, the Shape class gets another method,  
and the if statement keeps growing along with it.  
If Shape can draw 30 shapes, you'd need 30 similar methods in a single class. 

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
        # code to draw a circle

    def draw_square(self):
        # code to draw a square

    def draw_triangle(self):
        # code to draw a triangle
```

Let's use inheritance, as in the second sample.  
The Shape class's internals don't need to change when a new draw is added.  
To extend it, you just implement it in a class that inherits from Shape.  
The if-elif chain is gone, which makes maintenance easier too.

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
        # code to draw a circle

class Square(Shape):
    def __init__(self, size, color):
        super().__init__(color)
        self.size = size

    def draw(self):
        # code to draw a square

class Triangle(Shape):
    def __init__(self, base, height, color):
        super().__init__(color)
        self.base = base
        self.height = height

    def draw(self):
        # code to draw a triangle
```

You can see at a glance that extensibility and readability have improved.  
It's a basic concept, but pay attention to the basics.
