---
title: "[ Spring ] java web api server 만들기"
labels: ["Java","Kotlin","spring"]
published: true
date: 2023-12-07T20:21:50+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 205
tistoryUrl: "https://yeolceo.tistory.com/205"
tistoryCategory: "Java, Kotlin/spring"
tistoryTags: []
tistoryPostedAt: "2023-12-07 20:21:50"
language: ko
bloggerPostId: "8174568108357812595"
---
간단한 서버를 만들어봅시다

pakage에 controller를 만들어줍니다

그리고 거기서 bean으로 실행할 class하나를 만들어줍니다

restController를 통해 (controller에서 responseBody가합쳐진 annotation)

```crystal
package com.example.demo.controller;

import com.example.demo.bean.HelloWorldBean;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * rest contorller, 일반 contorller 차이는?
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

ㅇ
