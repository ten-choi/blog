---
title: "[ UrlDesign ] restapi 와 Url Design"
labels: ["Architecture"]
published: true
date: 2023-10-16T13:25:23+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 194
tistoryUrl: "https://yeolceo.tistory.com/194"
tistoryCategory: "Architecture/architecture"
tistoryTags: []
tistoryPostedAt: "2023-10-16 13:25:23"
language: ko
bloggerPostId: "8473492126687472379"
---
백엔드가 생각하는 이상적인 Rest Api와 Url Design을 찾아서..

## restapi 란

ㅁㄴㅇㄹ

## restapi 설계 규칙

1.  url은 동사보다는 명사를 사용해야한다
2.  대문자보단 소문자를 사용해야한다
3.  document의 이름은 단수명사를 사용한다 document의 이름? 은 뭐냐
4.  collection의 이름은 복수명사를 사용한다
5.  store의 이름? 은 복수명사 쓰라는데 이거 뭐냐

## Url Design의 목표

1.  url은 짧게 최소한의 url을 단서로
2.  설명적이며 해당 api 혹은 페이지의 역할을 유추할수있어야한다 
3.  구글 등의 검색 필터에 잘잡혀야한다

## Url Design 의 기술적 기초

1.  설명적이어야한다 이상적인url은 페이지의 컨탠츠와 일치하는 키워드를 사용하여 검색엔진과 사용자에게 포함된 내요에 단서를 제공한다 영어권일경우 예를들면 내가 typescript에 대해 검색하고있다 그런데 url이

underbar가 아닌 hyphen으로 url의 단어를 구분하세요

google에서 검색할경우 typescript, type-script, type\_script 이렇게 3개가 있으면 하이픈은 공백처럼 처리하지만

\_는 단어로서 처리한다고합니다. 즉 검색어로서 사용될때 \_는 불리해보이네요

typescript

설계 예시

대문자보단 소문자를 사용해야한다

마지막에 /를 넣지않는다 하지만 python djnago는 넣잖아? 

\_대신 dash인 - 를 사용한다고 한다 이건 미묘

파일 확장자는 uri에 포함하지않는다 이거는 당연

행위를 포함하지않는다 즉 post, delete이런거 그렇다고 post가 게시글 포스팅의 도메인적인 의미를 말하는것이 아니다 crud하는걸 적지말란소리다

## 페이지 매김 모범 사례를 염두에 두고 디자인

Google에서는 페이지가 매겨진 집합의 모든 URL이 단일 변경 변수(예: **example.com/category/page-1, example.com/category/page-2** )와 함께 동일한 URL 형식을 가져야 한다고 말합니다. [SEO에 대한 페이지 매김 모범 사례 가이드](https://www.deepcrawl.com/knowledge/technical-seo-library/pagination-seo-guide/) 에서 자세한 내용을 읽어보세요 .  
 페이징처리하면 뒤에 넘버가 저런식으로 붙어도된다는건데 url을 redirect해주는건지는 모르겠다 프론트에 보여줄 url이니까 

## 모바일 및 데스크톱 URL을 일관되게 유지하세요.

모바일용 별도 웹사이트가 있는 경우 모바일 페이지를 가리키는 데스크톱 페이지에 상대 대체 태그를 더 쉽게 추가할 수 있도록 각 사이트의 URL을 데스크톱과 최대한 일관되게 유지하는 것이 가장 좋습니다. 자세한 내용은 Google 개발자 ). 하위 도메인(예: **m.example.com** )에서 모바일 사이트를 호스팅하면 URL 경로를 동일하게 유지할 수 있습니다.

-   대소문자 불일치: /news 및 /NEWS
-   후행 슬래시 불일치: /news/ 및 /news
-   기본 경로 중복: example.com 및 example.com/index.html
-   중복된 URL 형식(친숙하지 않거나 친숙한 형식): example.com/category/subcategory/page.html 및 example.com/page
-   일관성 없는 순서: example.com/category-1/subcategory/page-1 및 example.com/category-2/page-1
-   HTTP/HTTPS/별칭 도메인
-   내부 링크가 손상되어 경로가 두 번 이상 반복되었습니다. 이러한 URL은 중복의 일반적인 원인이기 때문에 Google에서는 이러한 URL을 크롤링하거나 색인을 생성할 수 없습니다.
-   세션 ID: Google에서는 이를 별도의 URL로 처리하고 모든 단일 버전을 별도의 페이지로 크롤링하려고 시도하므로 크롤링 효율성이 떨어집니다. URL에서 동적 또는 세션 기반을 유지하세요. 이것이 가능하지 않은 경우 Search Console의 URL 매개변수 설정(크롤링 > URL 매개변수 아래)을 사용하여 Googlebot의 크롤링에서 제외되었는지 확인하세요.

collection에서 identify로 감

or example, “customers” is a collection resource and “customer” is a singleton resource (in a banking domain).

We can identify “customers” collec

참조

1.  [링크](https://www.lumar.io/blog/best-practice/guide-to-url-design/)
2.  링크
