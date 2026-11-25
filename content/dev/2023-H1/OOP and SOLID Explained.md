---
title: "OOP and SOLID Explained"
labels: ["architecture","oop","solid","srp","ocp","lsp","isp","dip","Archive"]
published: true
date: 2023-05-11T19:32:00-07:00
readerComments: "ALLOW"
language: en
bloggerPostId: "8050796008936059563"
originalUrl: "https://ten-logged.blogspot.com/2023/05/oop-solid.html"
source: "archive"
archivePath: "_archive/dev/code-design/OOP와 SOLID를 이해하기.md"
---

## What Is OOP?

OOP stands for object-oriented programming  
In other words, it's a way of developing that models real-world objects  
So what does that actually mean?

Let's use an example to make it easier  
Let's model "I drive a car" the OOP way  
The objects involved here are a driver and a car  
A car has parts like a steering wheel, accelerator, brake, engine, key, and gear shift  
The car then equips (inherits) whichever of those parts it needs  

Think of it as a way of developing where you split things into objects and clearly define each one  

In the real world, things like desks and chairs are what we call objects.  
The idea is to analyze the chair and the desk and apply that to development  
I'd like to apply it, but just saying "do object-oriented development" is vague  
You need to define the problem precisely  

## The 4 Characteristics of OOP

There are characteristics and there are principles  

The 4 characteristics are:  
Encapsulation  
Abstraction  
Inheritance  
Polymorphism

If you want the details on each characteristic, look them up on Google  
I think of the characteristics as passive rather than active when writing source code

## The 5 SOLID Principles

There are 5 principles  
These are active. It's best if you apply all of them  
They're called SOLID, after their first letters

OOP has 5 principles  
If your development doesn't violate these 5 principles, you can say you're doing OOP  
In other words, don't stare at "OOP" itself; satisfy the 5 principles  

I think applying OOP to code starts with understanding the characteristics and not breaking the principles  

### SRP - Single Responsibility Principle

A class or module should have a single responsibility

An example will make this easier  
Let's use ChatGPT to make some sample code  
Take a look at the first sample below  

class Customer:
    def \_\_init\_\_(self, name, email, phone):
        self.name = name
        self.email = email
        self.phone = phone
    
    def place\_order(self, order\_items):
        \# Validate and process the order
        pass
    
    def send\_email(self, subject, message):
        \# Send an email
        pass

This is a class where two other domains, order and emailService, are stuffed into the customer domain  
Say the order side gets more sophisticated  
The order domain will gain lookups, payments, refunds, partial refunds, validation, logging, and so on  
  
Assume the order-related source code grows past 80% of the class  
At that point, isn't it an order class rather than a customer class?  
Its purpose has become ambiguous  
You can no longer trust the class name  
  
The more features you add, the bigger the customer class below grows  
Code Gigantamax..  
Extensibility and readability suffer  

Let's look at the second version

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
        \# Code that checks whether the order is valid
        pass
    
    def process\_order(self):
        \# Code that processes the order
        pass

class EmailService:
    def send\_email(self, customer, subject, message):
        \# Send an email
        pass

Now each domain has a single responsibility  
The domains here are customer, order, and emailService

The better you split things by domain, the more stable development will be as features grow  
Let's not worry about file structure in this example  
At a glance, extensibility and readability are better

### OCP - Open-Closed Principle

A class or module should be open for extension but closed for modification  
Reading that alone, it's hard to tell what it means

Let's take an example  
Let's use ChatGPT to make some sample code  
Take a look at the first sample below  

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
        \# Code to draw a circle
    
    def draw\_square(self):
        \# Code to draw a square
    
    def draw\_triangle(self):
        \# Code to draw a triangle

Here's a class for the shape domain  
Every time a new kind of shape needs drawing, the shape class gets another method  
And the if statement keeps growing along with it  
If shape can draw 30 shapes, you have to create 30 similar methods in one class  
F... x..

Let's use inheritance, as in the second version  
The shape class doesn't need its source code changed when a new draw is added  
To extend it, you implement the new shape in a class that inherits from shape

The if-elif chain is gone, so maintenance is easier too  
At a glance, extensibility and readability are better  

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
        \# Code to draw a circle

class Square(Shape):
    def \_\_init\_\_(self, size, color):
        super().\_\_init\_\_(color)
        self.size = size
    
    def draw(self):
        \# Code to draw a square

class Triangle(Shape):
    def \_\_init\_\_(self, base, height, color):
        super().\_\_init\_\_(color)
        self.base = base
        self.height = height
    
    def draw(self):
        \# Code to draw a triangle

### LSP - Liskov Substitution Principle

A subtype must always be substitutable for its base type

Roughly, the base type is the class being inherited from, and the subtype is the class doing the inheriting  
An action performed on the subclass should behave the same way when performed through the superclass

Let's use ChatGPT to make sample source code that makes this easier to grasp  
Take a look at the first sample below

There's a rectangle class and a square class  
The square class inherits from the rectangle class  
For the principle to hold, passing the same parameters to either class should give the same result

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

// Create a Rectangle and a Square and print the result of each getArea() call
Rectangle rectangle = new Rectangle(4, 5);
System.out.println(rectangle.getArea()); // Output: 20

Square square = new Square(5);
System.out.println(square.getArea()); // Output: 25

// Code that tries to use a Square as if it were a Rectangle
Rectangle squareAsRectangle = new Square(5);
squareAsRectangle.setWidth(4);
squareAsRectangle.setHeight(5);
System.out.println(squareAsRectangle.getArea()); // Output: 25

The last result violates LSP  
One reason LSP matters is that when you violate it, you get a completely different result

Of course, the real problem is the design itself: building it this way just because  
the method signatures match, even though the classes are meant to produce different results

With the first sample, if a developer mixes up square and rectangle,  
there's no way to prevent that human error

Let's look at the second version  
There's a common getArea method that both use  
When you reuse the code like below, you avoid unexpected results  
In other words, reliability goes up

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

// Create a Rectangle and a Square and print the result of each getArea() call
Rectangle rectangle = new Rectangle(4, 5);
System.out.println(rectangle.getArea()); // Output: 20

### ISP - Interface Segregation Principle

A client should not depend on methods it doesn't use  
The wording is almost too simple  
An example should make it clearer

Let's use ChatGPT to make some sample code  
Take a look at the first sample below

public interface Vehicle {
    void changeGear();
    void startEngine();
    void stopEngine();
    void accelerate();
    void brake();
    void turnLeft();
    void turnRight();
}

Here's an interface with everything crammed into one place, without ISP  
A car class using that interface would have to implement every feature  
But what if cars come in stick and automatic?  
And changeGear only applies to stick?  
And my car is an automatic? Holy... sh  
  
You'd have to build parts into the car that it never uses  
Think about it physically and it really hits home  
It means my automatic car has a decorative 1st-to-5th gear stick that doesn't do anything..  
  
In the end, you get unnecessary dependencies and coupling  
Let's look at the second example  
It's clearly an example of the interface segregation principle in action

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

Just by splitting the interfaces like this, my automatic car doesn't have to inherit Gear  
That rules out any problems caused by operating a gear in an automatic car  
Then you use it like the car class below  
  
A split that lives up to the name ISP

public class Car implements Engine, Acceleratable, Brakeable, Turnable {
    @Override
    public void start() {
        // Code that starts the engine
    }

    @Override
    public void stop() {
        // Code that stops the engine
    }

    @Override
    public void accelerate() {
        // Code that accelerates
    }

    @Override
    public void brake() {
        // Code that hits the brake
    }

    @Override
    public void turnLeft() {
        // Code that turns left
    }

    @Override
    public void turnRight() {
        // Code that turns right
    }
}

### DIP - Dependency Inversion Principle

High-level modules should not depend on low-level modules, and abstractions should not depend on details  
In other words, both modules should depend on an abstraction, through an abstract interface  
That's ChatGPT's explanation.  

So what does that mean?  
Let's use ChatGPT to make some sample code  
Take a look at the first sample below  

public class OrderProcessor {
    private EmailSender emailSender = new EmailSender();

    public void processOrder(Order order) {
        // Order processing logic
        emailSender.sendEmail("Your order has been received.", order.getCustomerEmail());
    }
}

public class EmailSender {
    public void sendEmail(String message, String recipientEmail) {
        // Email sending logic
    }
}

Look at the code above  
Whenever you use the order method, the order notification has to go out by email  
That's how the source code is written

What if you want to send it through another channel instead of email?  
You'd have to modify the order method's logic and add a class for the other channel  
In other words, adding a low-level module's send behavior forces a change in the high-level order module  

Let's use an interface, as in the second example  
There are classes that send email and SMS

Because everything goes through the interface, the order class doesn't need to change  
To add a new feature, you implement a new class and inherit the interface  
It's decoupled, and extensibility goes up  

public class OrderProcessor {
    private IMessageSender messageSender;

    public OrderProcessor(IMessageSender messageSender) {
        this.messageSender = messageSender;
    }

    public void processOrder(Order order) {
        // Order processing logic
        messageSender.sendMessage("Your order has been received.", order.getCustomerEmail());
    }
}

public interface IMessageSender {
    void sendMessage(String message, String recipientEmail);
}

public class EmailSender implements IMessageSender {
    public void sendMessage(String message, String recipientEmail) {
        // Email sending logic
    }
}

public class SMSSender implements IMessageSender {
    public void sendMessage(String message, String recipientEmail) {
        // SMS sending logic
    }
}

## Wrapping Up

Having gone through all this, you can now judge whether you're actually doing OOP

Keep the characteristics in your head and apply the principles when you develop  
Plenty of people follow the principles without knowing them  
That may not cause any real problems, but  
I think you may need to understand the terminology when communicating about development
