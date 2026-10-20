---
title: "[ Java ] java jvm"
labels: ["Java","Kotlin","JVM"]
published: false
date: 2023-12-07T20:00:39+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 202
tistoryUrl: "https://yeolceo.tistory.com/202"
tistoryCategory: "Java, Kotlin/java"
tistoryTags: ["Java","KR","JVM"]
tistoryPostedAt: "2023-12-07 20:00:39"
language: ko
bloggerPostId: "1397337430776552928"
---
jvm이란

즉 자바 가상 머신은 OS와 Java 애플리케이션 간의 중개자 역할을 수행하는 핵심적인 기술입니다. 이는 자바 바이트코드를 실행하기 위한 환경을 제공하여, 자바 프로그램이 플랫폼에 독립적으로 실행될 수 있도록 해줍니다.  

JVM의 구성은 다음과 같습니다.

Class Loader(클래스 로더): 클래스 파일을 로드하고 링크하여 JVM 내부에 배치하는 역할을 합니다. Runtime 시점에 클래스를 로딩하고 인스턴스를 생성할 때 클래스 로더가 메모리에 로드합니다.  

Execution Engine(실행 엔진): 로드된 클래스의 바이트코드를 실행하는 런타임 모듈입니다. 실행 엔진은 자바 바이트 코드를 명령어 단위로 읽고 실행하는 역할을 수행합니다. 이때 Interpreter(인터프리터)와 JIT Compiler 방식을 사용합니다.  

Interpreter(인터프리터): 소스 코드를 직접 실행하는 프로그램으로, 자바는 인터프리터 방식을 통해 바이트 코드를 해석하여 실행합니다. 이 방식은 한 줄씩 실행되어 속도가 상대적으로 느린 편입니다.  

JIT Compiler (Just In Time Compiler): 인터프리터 방식의 속도 문제를 개선하기 위해 도입된 컴파일러입니다. 바이트코드를 컴파일하여 네이티브 코드로 변환하므로 빠른 실행 속도를 제공합니다.  

Garbage Collector(가비지 컬렉터): 가비지 컬렉터는 메모리 정리를 담당하여 사용되지 않는 가비지를 정리하는 역할을 합니다. 이는 중요한 메모리 관리 기능 중 하나입니다.  

Runtime Data Area: JVM이 프로그램을 실행하기 위해 할당받은 메모리 공간으로, PC Register, JVM Stack, Native Method Stack, Method Area, Heap 등으로 나뉩니다.  

이런 구성요소들이 JVM의 핵심을 이루며, 자바 어플리케이션의 실행 및 관리를 담당합니다.
