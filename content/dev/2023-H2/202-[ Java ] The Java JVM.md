---
title: "[ Java ] The Java JVM"
labels: ["Java","Kotlin","JVM","Archive"]
published: true
date: 2023-12-07T20:00:39+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 202
tistoryUrl: "https://yeolceo.tistory.com/202"
tistoryCategory: "Java, Kotlin/java"
tistoryTags: ["Java","KR","JVM"]
tistoryPostedAt: "2023-12-07 20:00:39"
language: en
bloggerPostId: "1397337430776552928"
---
What is the JVM?

The Java Virtual Machine is a core technology that acts as the intermediary between the OS and Java applications. It provides an environment for running Java bytecode, which lets Java programs run independently of the platform.  

The JVM is made up of the following:

Class Loader: Loads and links class files and places them inside the JVM. At runtime, when classes are loaded and instances are created, the class loader loads them into memory.  

Execution Engine: The runtime module that executes the bytecode of loaded classes. It reads and executes Java bytecode instruction by instruction, using both an Interpreter and a JIT Compiler.  

Interpreter: A program that executes code directly. Java uses an interpreter to interpret and execute bytecode. Since it runs line by line, it's relatively slow.  

JIT Compiler (Just In Time Compiler): A compiler introduced to fix the interpreter's speed problem. It compiles bytecode into native code, which runs much faster.  

Garbage Collector: The garbage collector handles memory cleanup by clearing out garbage that's no longer used. It's one of the key memory management features.  

Runtime Data Area: The memory space the JVM is allocated to run a program, divided into the PC Register, JVM Stack, Native Method Stack, Method Area, Heap, and so on.  

These components form the core of the JVM and are responsible for running and managing Java applications.
