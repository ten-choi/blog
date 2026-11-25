---
title: "[ DesignPattern ] What Is SRP?"
labels: ["Architecture","design_pattern","OOP","solid","SRP","DesignPattern","Archive"]
published: true
date: 2023-05-11T16:13:24+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 167
tistoryUrl: "https://yeolceo.tistory.com/167"
tistoryCategory: "Architecture/design_pattern"
tistoryTags: ["architecture","OOP","solid","KR","SRP","DesignPattern"]
tistoryPostedAt: "2023-05-11 16:13:24"
language: en
bloggerPostId: "2933601435494428310"
---
SRP: Single Responsibility Principle. It says a class or module should have only one responsibility. You might wonder what that even means.

Let's use ChatGPT to make some sample code.  
Take a look at the first sample below.

```ruby
class Customer:
    def __init__(self, name, email, phone):
        self.name = name
        self.email = email
        self.phone = phone

    def place_order(self, order_items):
        # validate and process the order
        pass

    def send_email(self, subject, message):
        # send the email
        pass
```

This class puts two other actors, order and emailService, inside the customer actor.  
Code like that already makes me uncomfortable, but let's bear with it for a moment...  
Say the order side gets more sophisticated.  
The order actor would gain lookups, payments, refunds, partial refunds, validation, logging, and more.  

Suppose order-related code grows past 80% of the class.  
Then isn't it really an Order class rather than a Customer class?  
When the responsible actor gets blurry, the class name becomes less trustworthy too.  

And as things get more sophisticated, the Customer class below will get truly huge.  
Adding code to that class to extend it would be painful, and it would be painful for others to read.

Give each actor a single responsibility.  
The actors here are customer, order, and emailService.  
Just splitting them into separate classes makes development stable as things grow more sophisticated.  
Let's not worry about file structure for this example.

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
        # code to validate the order
        pass

    def process_order(self):
        # code to process the order
        pass

class EmailService:
    def send_email(self, customer, subject, message):
        # send the email
        pass
```

You can see at a glance that extensibility and readability have improved.  
It's a basic concept, but the basics matter.
