---
title: "Topic: What Is the DIP?"
labels: ["Archive"]
published: true
date: 2023-05-12T14:20:49+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 169
tistoryUrl: "https://yeolceo.tistory.com/169"
tistoryCategory: ""
tistoryTags: []
tistoryPostedAt: "2023-05-12 14:20:49"
language: en
bloggerPostId: "492857020996402371"
---
#### **Topic: What is the DIP**  

DIP: Dependency Inversion Principle  
High-level modules should not depend on low-level modules, and abstractions should not depend on details  
In other words, both modules should depend on an abstraction, through an abstract interface  
That's ChatGPT's explanation.

So what does that mean?  
Let's use ChatGPT to make some sample code  
Take a look at the first sample below

```java
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
```

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

```java
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
```
