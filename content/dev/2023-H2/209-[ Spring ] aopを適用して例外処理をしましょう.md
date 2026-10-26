---
title: "[ Spring ] aopを適用して例外処理をしましょう"
labels: ["Java","Kotlin","spring","AOP","jp"]
published: false
date: 2023-12-11T21:59:14+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 209
tistoryUrl: "https://yeolceo.tistory.com/209"
tistoryCategory: "Java, Kotlin/spring"
tistoryTags: ["Java","AOP","Spring","jp"]
tistoryPostedAt: "2023-12-11 21:59:14"
language: ja
bloggerPostId: "8916589479908537659"
---
## **What is the AOP**

AOPとは、Aspect Oriented Programmingの略語で、「観点指向プログラミング」と呼ばれます。 

観点指向は簡単に言えば、あるロジックを基準に核心的な観点、付加的な観点に分けて見て、その観点を基準にそれぞれモジュール化するということです。

ここでモジュール化とは、ある共通のロジックや機能を一つの単位にまとめることを言います。

例えば、核心的な観点は結局、私たちが適用しようとする核心ビジネスロジックになります。

また、付加的な観点としては、コアロジックを実行するために行われるデータベース接続、ロギング、ファイル入出力などが挙げられます。

## **Create error api**

beanで管理するapiを作ってみましょう。

そして呼び出す時、以下のようにエラーを発生させてみましょう。

```typescript
@RestController
public class HelloWorldController {

    @GetMapping(path = "/hello-world")
    public HelloWorldBean helloWorldBean() {
        throw new RuntimeException("this is test error");
    }
}
```

## **Create exception response class**

exception Responseの基本的な形態を作ってくれます。

error Created At, error Title, error Detailをreturnするclassを作ります。

深く作るとissueLevel、issueTagなどすることが多くなるので、  
今後追加文書に適用する予定です 。

1.  @Data: Lombokのannotationでgetter、setterなどを簡単に作ってくれます 。
2.  @AllArgsConstructor: 該当class内に存在するすべてのフィールドをパラメータとする生成子を作ってくれます。
3.  @NoArgsConstructor:  パラメーターを持たない基本生成子を生成します。

```typescript
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ExceptionResponse {

    private String title;
    private String detail;
    private Date createdAt;
}
```

## **Create exception handler**

ExceptionHandlerを作ります。

1.  @RestControllerAdvice: @Componentの特殊なケースで、SpringBootapplicationでグローバルに例外をハンドリングできるannotationです。
2.  @ExceptionHandler: Beanで発生する例外をつかみ、1つのメソッドで処理するannotationです。

```typescript
@RestControllerAdvice
public class CustomizedResponseEntityExceptionHandler extends ResponseEntityExceptionHandler {

    @ExceptionHandler(Exception.class)
    public final ResponseEntity<Object> handleAllExceptions(Exception ex, WebRequest request) {
        ExceptionResponse exceptionResponse = new ExceptionResponse(ex.getMessage(), request.getDescription(true), new Date());
        return new ResponseEntity<>(exceptionResponse, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
```

## **Testing**

postManを使ってapiテストを行います。

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/209/img.webp)

今後errTag、errLevel、errLogging、sendSlackなどを追加で文書化する予定です。
