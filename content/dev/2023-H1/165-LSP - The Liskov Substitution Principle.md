---
title: "LSP: The Liskov Substitution Principle"
labels: ["Archive"]
published: true
date: 2023-05-09T18:19:06+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 165
tistoryUrl: "https://yeolceo.tistory.com/165"
tistoryCategory: ""
tistoryTags: []
tistoryPostedAt: "2023-05-09 18:19:06"
language: en
bloggerPostId: "855839609449544419"
---
#### Topic: What Is LSP  

LSP: Liskov Substitution Principle  
It's the principle that a subtype must always be substitutable for its base type.  

Intuitively, the base type is the class being inherited from, and the subtype is the class that inherits.  
I take it to mean that an operation performed via the subclass should behave the same when performed via the superclass.  

Let's use ChatGPT to make some sample code.  
Take a look at the first sample below.

There are Rectangle and Square classes.  
Square inherits from Rectangle.  
To follow the principle, either class should produce the same result given the same parameters.  
Java seems like the easiest language to explain this in.

```java
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
        return width * height;
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

// Create a Rectangle and a Square and print the result of calling getArea() on each
Rectangle rectangle = new Rectangle(4, 5);
System.out.println(rectangle.getArea()); // Output: 20

Square square = new Square(5);
System.out.println(square.getArea()); // Output: 25

// Code that tries to use a Square as if it were a Rectangle
Rectangle squareAsRectangle = new Square(5);
squareAsRectangle.setWidth(4);
squareAsRectangle.setHeight(5);
System.out.println(squareAsRectangle.getArea()); // Output: 25
```

The last result violates LSP.  
One reason LSP matters: if a developer accidentally plugs in an object like that, you get a completely different result.  
And I think the design is already flawed when it applies the same width/height setters to classes meant to produce different results,  
just because their methods share the same names.

Let's look at the second sample.  
There's a common getArea method that both use.  
When you reuse code like below, you avoid unexpected results.  
So I think the upside is better reliability.

```java
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
        return width * height;
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
        return size * size;
    }
}

// Create a Rectangle and a Square and print the result of calling getArea() on each
Rectangle rectangle = new Rectangle(4, 5);
System.out.println(rectangle.getArea()); // Output: 20
```

It's not a special rule, but code that prevents human error matters.
