---
title: "[ Spring ] The Relationship Between the IoC Container and Beans"
labels: ["Java","Kotlin","spring","DI","bean","IoCContainer","Archive"]
published: true
date: 2023-12-07T19:39:04+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 201
tistoryUrl: "https://yeolceo.tistory.com/201"
tistoryCategory: "Java, Kotlin/spring"
tistoryTags: ["Java","Spring","DI","bean","KR","IoCContainer"]
tistoryPostedAt: "2023-12-07 19:39:04"
language: en
bloggerPostId: "6748122215786148123"
---
## **What Is a Bean?**

A bean is a reusable Java object managed by the Spring container.

It's an instantiated object of a class. Through Spring annotations, objects returned from methods get registered in the Spring container. A bean is used in the container along with its class registration info, including getter/setter methods.

In real code you don't access beans directly; you access them indirectly through the getBean() method Spring provides. The IoC container manages the beans and keeps control over the objects the application needs.

## **What Is an IoC Container?**

Inversion of Control (IoC) is one of the core concepts in software engineering: handing control of the program entirely over to another system or framework. An IoC container puts this into practice by managing object lifecycles and dependency injection, taking over control of the application.  

In the Spring Framework, the IoC container is called the ApplicationContext, also known as the Spring container or the DI (Dependency Injection) container. It handles creating objects (beans), injecting dependencies, managing them, and disposing of them, and it does so under the container's authority rather than your code's.  

In other words, instead of your code handling lifecycle-related work directly, the Spring container takes care of it, so control has been inverted. That's why the Spring container is also called the IoC container.  

## **What Is DI?**

Dependency

Dependency injection separates a client's dependency on how its dependencies are created from the client's behavior, which keeps the program design loosely coupled and helps it follow the Dependency Inversion Principle and the Single Responsibility Principle.
