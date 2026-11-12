---
title: "[ Spring ] spring 에 swagger 적용하기"
labels: ["Java","Kotlin","Spring","jp","Swagger"]
published: true
date: 2023-12-07T20:22:03+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 206
tistoryUrl: "https://yeolceo.tistory.com/206"
tistoryCategory: "Java, Kotlin"
tistoryTags: ["Java","Spring","jp","Swagger"]
tistoryPostedAt: "2023-12-07 20:22:03"
language: ja
bloggerPostId: "1332408222697398211"
---
## **What is the Swagger**

Swaggerは、開発者がRestWebサービスを設計、ビルド、文書化することを支援するフレームワークです。  
一人で開発するのではなく協業する場合、APIを提供したり既存のAPIを分析しなければなりませんが、この時Swaggerを通じてAPI情報を確認することができます。  

プロジェクトを進めながら協業する際に必要なapi明細ライブラリーです  

プロジェクトを進めながらフロントと協業する際、APIの明細として使いやすいswaggerを導入しようと思います  

spring 3.0.0以上のバージョンで使おうと思います  

下はリリース日を見ると止まっています これ以上アップデートしません

springFox [https://github.com/springfox/springfox](https://github.com/springfox/springfox)

springDoc  [https://github.com/springdoc/springdoc-openapi](https://github.com/springdoc/springdoc-openapi)

どちらも有名ですが、アップデートを継続的に行うspringdocを使って進めます

## How to apply it

gradleで進行してdependenciesに追加しましょう

gradleをダウンロードするとすぐにサーバーを実行し、以下のリンクに入るとswaggerが実行されるのを見ることができます  

http://localhost:8080/swagger-ui/index.html  

pathを変えて/api-docsでアプローチするように進めます

어노테이션 설명

<table style="background-color: #ffffff; color: #353638; text-align: left; border-collapse: collapse; width: 100%;" border="1" data-ke-style="style2" data-ke-align="alignLeft"><tbody><tr><td style="color: #000000;"><b>Annotation</b></td><td style="color: #000000;"><b>Parameter</b></td><td style="color: #000000;"><b>Explain</b></td></tr><tr><td style="color: #000000;"><b>@Tag</b></td><td style="color: #000000;">&nbsp;</td><td style="color: #000000;">Controller에 대한 설명을 명시하는 어노테이션</td></tr><tr><td style="color: #000000;">&nbsp;</td><td style="color: #000000;">name</td><td style="color: #000000;">API 그룹의 이름을 지정하는 속성</td></tr><tr><td style="color: #000000;">&nbsp;</td><td style="color: #000000;">description</td><td style="color: #000000;">API 그룹의 설명을 지정하는 속성</td></tr><tr><td style="color: #000000;"><b>@Operation</b></td><td style="color: #000000;">&nbsp;</td><td style="color: #000000;">API 그룹 내에 각각의 API를 명시하는 어노테이션</td></tr><tr><td style="color: #000000;">&nbsp;</td><td style="color: #000000;">summary</td><td style="color: #000000;">API에 대한 간략한 설명을 지정하는 속성</td></tr><tr><td style="color: #000000;">&nbsp;</td><td style="color: #000000;">description</td><td style="color: #000000;">API에 대한 상세 설명을 지정하는 속성</td></tr><tr><td style="color: #000000;">&nbsp;</td><td style="color: #000000;">response</td><td style="color: #000000;">API에 대한 응답을 지정하는 속성</td></tr><tr><td style="color: #000000;">&nbsp;</td><td style="color: #000000;">parameter</td><td style="color: #000000;">API에 대한 파라미터를 지정하는 속성</td></tr><tr><td style="color: #000000;"><b>@Schema</b></td><td style="color: #000000;">&nbsp;</td><td style="color: #000000;">모델에 대한 설명을 명시하는 어노테이션</td></tr><tr><td style="color: #000000;">&nbsp;</td><td style="color: #000000;">description</td><td style="color: #000000;">모델 자체 혹은 컬럼에 대한 설명을 하는 속성</td></tr></tbody></table>

```typescript
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
