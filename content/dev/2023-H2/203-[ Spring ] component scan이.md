---
title: "[ Spring ] component scan이"
labels: ["Java","Kotlin","spring","ComponentScan"]
published: false
date: 2023-12-07T20:08:11+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 203
tistoryUrl: "https://yeolceo.tistory.com/203"
tistoryCategory: "Java, Kotlin/spring"
tistoryTags: ["Java","Spring","KR","ComponentScan"]
tistoryPostedAt: "2023-12-07 20:08:11"
language: ko
bloggerPostId: "8838694749424494347"
---
컴포넌트 스캔(Component Scan)은 스프링에서 스프링 빈(Bean)으로 등록될 준비가 된 클래스들을 자동으로 스캔하여 빈으로 등록하는 프로세스를 의미합니다.  

일반적으로 @Component 어노테이션이 부착된 클래스들이 컴포넌트 스캔의 대상이 됩니다. 하지만 @Configuration, @Service, @Repository, @Controller 등의 어노테이션에는 @Component가 포함되어 있어서 이들 어노테이션이 붙은 클래스들도 자동으로 컴포넌트 스캔의 대상이 됩니다.  

@ComponentScan과 컴포넌트 스캔의 범위를 정의하기 위해서는 설정 정보 클래스에 @ComponentScan 어노테이션을 추가해야 합니다. 이때, 컴포넌트 스캔의 범위는 설정 정보 클래스가 속한 패키지를 포함한 모든 하위 패키지입니다. 그러나 모든 자바 클래스를 전부 컴포넌트 스캔하면 시간이 많이 소요될 수 있습니다. 따라서 아래와 같이 시작 위치를 명시하여 스캔할 패키지의 위치를 지정할 수 있습니다.  

java  
Copy code  
@ComponentScan(basePackages = "hello.core")  
또한, 스프링 부트를 사용할 경우, 보통 스프링 부트의 대표적인 시작 정보인 @SpringBootApplication 어노테이션을 프로젝트의 최상위 루트 위치에 두는 것이 관례입니다. @SpringBootApplication 어노테이션에는 @ComponentScan이 내장되어 있기 때문에 해당 어노테이션이 붙은 클래스는 하위 패키지를 모두 컴포넌트 스캔의 대상으로 삼습니다.
