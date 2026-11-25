---
title: "[ Spring ] Types of Annotations"
labels: ["Java","Kotlin","spring","Archive"]
published: true
date: 2023-12-07T20:21:38+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 204
tistoryUrl: "https://yeolceo.tistory.com/204"
tistoryCategory: "Java, Kotlin/spring"
tistoryTags: []
tistoryPostedAt: "2023-12-07 20:21:38"
language: en
bloggerPostId: "6933926180254430044"
---
What is an annotation?

Going by the English word alone, it means a note or comment. In Java, though, it's used as a feature rather than just a comment.

It's a concept like a library that you can add to your Java source code.

When you add it to source code, it acts as functionality, not as a comment.

Since it's written like a comment, it's concise, which helps with readability and productivity.

Spring's main annotations

component

The annotation used to register a class you wrote as a Spring bean.

Once registered as a bean, it's managed by Spring's IoC container.

```java
@Component
public String test(){

return ""
}
```

@ComponentScan

When Spring finds a class registered with at least one of @Component, @Service, @Repository, @Controller, or @Configuration, it registers it in the Context as a bean. It scans for classes to be registered as beans under the class carrying the @ComponentScan annotation and registers them as beans.

@Bean

Used when you need to turn an external library, which you can't control, into a bean.

@Controller

An annotation that registers the class as a Spring bean and declares the class's role.

@RequestHeader

An annotation that reads a header value from an API request; you pass the header name in value on the parameter.

```java
@Controller                   // This class acts as a controller
@RequestMapping("/user")      // This class handles every request coming in to /user
public class UserController {
    @RequestMapping(method = RequestMethod.GET)
    public String getUser(@RequestHeader(value="Accept-Language") String acceptLanguage) {
        //  handles GET /user
    }
}
```

### @RequestMapping

Written as @RequestMapping(value=""). When the incoming request URI matches the annotation's value, that class or method runs. It can be applied to classes and methods in a Controller, and is used as shown below.

-   Applied at the class level, it applies to all methods underneath.
-   Applied to a method, that method handles the URI the way it specifies.

```java
@Controller                   // This class acts as a controller
@RequestMapping("/user")      // This class handles every request coming in to /user
public class UserController {
    @RequestMapping(method = RequestMethod.GET)
    public String getUser(Model model) {
        //  handles GET /user
    }
    @RequestMapping(method = RequestMethod.POST)
    public String addUser(Model model) {
        //  handles POST /user
    }
    @RequestMapping(value = "/info", method = RequestMethod.GET)
    public String addUser(Model model) {
        //  handles GET /user/info
    }
}
```

### @RequestParam

An annotation that matches parameters passed in the URL to method arguments so you can receive and handle them, used as shown below. It converts a JSON body into a Java object via a MessageConverter.

```java
@Controller                   // This class acts as a controller
@RequestMapping("/user")      // This class handles every request coming in to /user
public class UserController {
    @RequestMapping(method = RequestMethod.GET)
    public String getUser(@RequestParam String nickname, @RequestParam(name="old") String age) {
        // handles GET /user
        // https://naver.com?nickname=dog&old=10
        String sub = nickname + "_" + age;
        ...
    }
}
```

### @RequestBody

An annotation that matches data passed in the body to a method argument so you can receive and handle it. It converts the HTTP request body sent by the client (JSON, XML, etc.) into a Java object. It's used as shown below.

When the client sends a value (usually an object) in the body as **JSON or XML**, it gets converted into a Java object.

```java
@Controller                   // This class acts as a controller
@RequestMapping("/user")      // This class handles every request coming in to /user
public class UserController {
    @RequestMapping(method = RequestMethod.POST)
    public String addUser(@RequestBody User user) {
        //  handles POST /user
        String sub_name = user.name;
        String sub_old = user.old;
    }
}
```

### @ModelAttribute

Binds the HTTP parameters and body sent by the client to an object 1:1 through setter methods. Unlike @RequestBody, it requires the HTTP body to be **multipart/form-data**. While @RequestBody accepts JSON, @ModelAttribute can't accept and process JSON.

### @ResponseBody

With @ResponseBody, the method's return value isn't rendered as a View; it's written directly to the HTTP response body. It returns data such as JSON or XML.

```java
@Controller                   // This class acts as a controller
@RequestMapping("/user")      // This class handles every request coming in to /user
public class UserController {
    @RequestMapping(method = RequestMethod.GET)
    @ResponseBody
    public String getUser(@RequestParam String nickname, @RequestParam(name="old") String age) {
        // handles GET /user
        // https://naver.com?nickname=dog&old=10
        User user = new User();
        user.setName(nickname);
        user.setAge(age);
        return user;
    }
}
```

### @Autowired

There are three main ways to get a bean injected in the Spring Framework, listed below. @Autowired is used to have a bean injected. Spring looks at the class and injects a bean that matches by type (it checks the type first, then the name if there's no match).

-   @Autowired
-   Constructor (using @AllArgsConstructor)
-   Setter

### @GetMapping

Does exactly the same thing as RequestMapping(method=RequestMethod.GET), used as shown below.

```java
@Controller                   // This class acts as a controller
@RequestMapping("/user")      // This class handles every request coming in to /user
public class UserController {
    @GetMapping("/")
    public String getUser(Model model) {
        //  handles GET /user
    }

    ////////////////////////////////////
    // The methods above and below behave identically. //
    ////////////////////////////////////

    @RequestMapping(method = RequestMethod.GET)
    public String getUser(Model model) {
        //  handles GET /user
    }
}
```

### @PostMapping

Does exactly the same thing as RequestMapping(method=RequestMethod.POST), used as shown below.

```java
@Controller                   // This class acts as a controller
@RequestMapping("/user")      // This class handles every request coming in to /user
public class UserController {
    @RequestMapping(method = RequestMethod.POST)
    public String addUser(Model model) {
        //  handles POST /user
    }

    ////////////////////////////////////
    // The methods above and below behave identically. //
    ////////////////////////////////////

    @PostMapping("/")
    public String addUser(Model model) {
        //  handles POST /user
    }
}
```

### @SpringBootTest

Provides the dependencies needed for Spring Boot tests.

```java
// DemoApplicationTests.java
package com.example.demo;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class DemoApplicationTests {

	@Test
	void contextLoads() {

	}

}
```

### @Test

Marks what JUnit should test.

## 3\. Common Lombok Annotations and What They Do

Lombok is a library that cuts down a lot of code, which greatly improves readability. Its main annotations are below.

### @Setter

Generates setter methods for every field in the class.

### @Getter

Generates getter methods for every field in the class.

### @AllArgsConstructor

Adds a constructor that takes every field in the class as a parameter.

### @NoArgsConstructor

Automatically adds a default constructor to the class.

### @ToString

Generates a toString method covering every field in the class.
