---
title: "[ Architecture ] My Journey to Understanding OOP and SOLID"
labels: ["Architecture","design_pattern","OOP","solid","DesignPattern","Archive"]
published: true
date: 2023-05-12T11:32:59+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 168
tistoryUrl: "https://yeolceo.tistory.com/168"
tistoryCategory: "Architecture/design_pattern"
tistoryTags: ["architecture","OOP","solid","KR","DesignPattern"]
tistoryPostedAt: "2023-05-12 11:32:59"
language: en
bloggerPostId: "1311557868169956902"
---
### What Is OOP?

It stands for object-oriented programming  
In other words, it's a way of developing that models real-world objects. So what does that actually mean?  
Let's use an example to make it easier. Let's model "I drive a car" the OOP way

The objects involved here are a driver and a car  
A car has parts like a steering wheel, accelerator, brake, engine, key, and gear shift  
The car then equips (inherits) whichever of those parts it needs  
Think of it as a way of developing where you split things into objects and clearly define each one

There are characteristics and there are principles. The 4 characteristics are:  
Encapsulation  
Abstraction  
Inheritance  
Polymorphism

If you want the details on each characteristic, look them up on Google  
I think of the characteristics as passive rather than active when writing source code

### The 5 Principles  

These are active. That means you have to actually use them as you write code  
It takes more effort, but applying all of them is logically sound. They're called SOLID, after their first letters  
When applying OOP to code, what matters is understanding the characteristics and not breaking the principles  
Here are links to my notes on each

-   SRP: [SRP](https://yeolceo.tistory.com/167)
-   OCP: [OCP](https://yeolceo.tistory.com/164)
-   LSP: [LSP](https://yeolceo.tistory.com/165)
-   ISP: [ISP](https://yeolceo.tistory.com/166)
-   DIP: [DIP](https://yeolceo.tistory.com/169)

Keep the characteristics in your head and apply the principles when you develop. Plenty of people follow the principles without knowing them  
That may not cause any real problems, but I think you may need to understand the terminology when communicating about development
