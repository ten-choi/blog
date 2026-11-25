---
title: "[ Spring ] Building a Java Web API Server"
labels: ["Java","Kotlin","spring","Archive"]
published: true
date: 2023-12-07T20:21:50+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 205
tistoryUrl: "https://yeolceo.tistory.com/205"
tistoryCategory: "Java, Kotlin/spring"
tistoryTags: []
tistoryPostedAt: "2023-12-07 20:21:50"
language: en
bloggerPostId: "8174568108357812595"
---
Let's build a simple server.

Create a controller package.

Then create a class in it that'll run as a bean.

Using @RestController (an annotation that combines @Controller with @ResponseBody):

```java
package com.example.demo.controller;

import com.example.demo.bean.HelloWorldBean;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * What's the difference between a rest controller and a regular controller?
 */
@RestController
public class HelloWorldController {

    //GET
    //
//    @RequestMapping(method = RequestMethod.GET, path = "/asdf")
    @GetMapping(path = "/hello-world")
    public String helloWorld() {
        return "test";
    }

    @GetMapping(path = "/hello-world-bean")
    public HelloWorldBean helloWorldBean() {
        return new HelloWorldBean("hello");
    }
}
```

d
