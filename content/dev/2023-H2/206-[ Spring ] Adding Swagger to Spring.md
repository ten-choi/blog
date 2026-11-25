---
title: "[ Spring ] Adding Swagger to Spring"
labels: ["Java","Kotlin","Spring","jp","Swagger","Archive"]
published: true
date: 2023-12-07T20:22:03+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 206
tistoryUrl: "https://yeolceo.tistory.com/206"
tistoryCategory: "Java, Kotlin"
tistoryTags: ["Java","Spring","jp","Swagger"]
tistoryPostedAt: "2023-12-07 20:22:03"
language: en
bloggerPostId: "1332408222697398211"
---
## **What Is Swagger?**

Swagger is a framework that helps developers design, build, and document RESTful web services.  
When you're collaborating rather than working solo, you have to provide APIs or analyze existing ones, and Swagger lets you check that API information.  

It's an API spec library you need when collaborating on a project.  

I'm going to bring in Swagger, since it's an easy way to share API specs when working with the frontend on a project.  

I plan to use it with Spring 3.0.0 or later.  

Looking at the release dates, the first one below has stalled. It's no longer being updated.

springFox [https://github.com/springfox/springfox](https://github.com/springfox/springfox)

springDoc  [https://github.com/springdoc/springdoc-openapi](https://github.com/springdoc/springdoc-openapi)

Both are well known, but I'll go with springdoc since it's still actively updated.

## How to Apply It

We're using Gradle, so add it to dependencies.

Once Gradle pulls it down, start the server right away and open the link below to see Swagger running.  

http://localhost:8080/swagger-ui/index.html  

We'll change the path so it's reached via /api-docs.

Annotation reference

<table style="background-color: #ffffff; color: #353638; text-align: left; border-collapse: collapse; width: 100%;" border="1" data-ke-style="style2" data-ke-align="alignLeft"><tbody><tr><td style="color: #000000;"><b>Annotation</b></td><td style="color: #000000;"><b>Parameter</b></td><td style="color: #000000;"><b>Explain</b></td></tr><tr><td style="color: #000000;"><b>@Tag</b></td><td style="color: #000000;">&nbsp;</td><td style="color: #000000;">Annotation that describes a Controller</td></tr><tr><td style="color: #000000;">&nbsp;</td><td style="color: #000000;">name</td><td style="color: #000000;">Sets the name of the API group</td></tr><tr><td style="color: #000000;">&nbsp;</td><td style="color: #000000;">description</td><td style="color: #000000;">Sets the description of the API group</td></tr><tr><td style="color: #000000;"><b>@Operation</b></td><td style="color: #000000;">&nbsp;</td><td style="color: #000000;">Annotation that describes each API within an API group</td></tr><tr><td style="color: #000000;">&nbsp;</td><td style="color: #000000;">summary</td><td style="color: #000000;">Sets a short summary of the API</td></tr><tr><td style="color: #000000;">&nbsp;</td><td style="color: #000000;">description</td><td style="color: #000000;">Sets a detailed description of the API</td></tr><tr><td style="color: #000000;">&nbsp;</td><td style="color: #000000;">response</td><td style="color: #000000;">Sets the API's response</td></tr><tr><td style="color: #000000;">&nbsp;</td><td style="color: #000000;">parameter</td><td style="color: #000000;">Sets the API's parameters</td></tr><tr><td style="color: #000000;"><b>@Schema</b></td><td style="color: #000000;">&nbsp;</td><td style="color: #000000;">Annotation that describes a model</td></tr><tr><td style="color: #000000;">&nbsp;</td><td style="color: #000000;">description</td><td style="color: #000000;">Describes the model itself or a column</td></tr></tbody></table>

```java
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;

@Configuration
public class SwaggerConfig {
    @Bean
    public OpenAPI openAPI() {
        Info info = new Info()
                .title("Test Project API Document")
                .version("v0.0.1")
                .description("This is description this project of Swagger");
        return new OpenAPI()
                .components(new Components())
                .info(info);
    }

}
```
