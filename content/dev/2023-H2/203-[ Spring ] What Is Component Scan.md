---
title: "[ Spring ] What Is Component Scan?"
labels: ["Java","Kotlin","spring","ComponentScan","Archive"]
published: true
date: 2023-12-07T20:08:11+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 203
tistoryUrl: "https://yeolceo.tistory.com/203"
tistoryCategory: "Java, Kotlin/spring"
tistoryTags: ["Java","Spring","KR","ComponentScan"]
tistoryPostedAt: "2023-12-07 20:08:11"
language: en
bloggerPostId: "8838694749424494347"
---
Component scan is the process in Spring of automatically scanning for classes that are ready to be registered as Spring beans and registering them as beans.  

Classes annotated with @Component are generally the targets of component scan. But annotations like @Configuration, @Service, @Repository, and @Controller include @Component, so classes with those annotations are automatically picked up by component scan as well.  

To define @ComponentScan and the scope of component scanning, you add the @ComponentScan annotation to a configuration class. The scan covers the package the configuration class lives in, plus all its subpackages. But scanning every single Java class can take a long time, so you can specify where to start, like this:  

```java
@ComponentScan(basePackages = "hello.core")
```

Also, when using Spring Boot, the convention is to put the @SpringBootApplication annotation, Spring Boot's main entry point, at the top-level root of the project. Since @SpringBootApplication has @ComponentScan built in, the class carrying it makes all subpackages targets for component scanning.
