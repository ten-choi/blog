---
title: "[ Spring ] What Is Spring Batch?"
labels: ["Archive"]
published: true
date: 2023-12-07T20:22:24+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 207
tistoryUrl: "https://yeolceo.tistory.com/207"
tistoryCategory: ""
tistoryTags: []
tistoryPostedAt: "2023-12-07 20:22:24"
language: en
bloggerPostId: "8333892284557751566"
---
Spring Batch has a huge number of settings and features. In this post I'll cover the basics of Spring Batch and walk through an example of using it. The goal is that even someone who's never used Spring Batch can read this and start using it in a simple way; the various settings and extra features are best explored and studied as you work on a project.

# **Spring Batch**

Spring Batch provides the features essential for processing large volumes of records: logging/tracing, transaction management, job processing statistics, job restart, skipping, resource management, and more. It also offers advanced technical services and features that enable high-volume, high-performance batch jobs through optimization and partitioning techniques.

In Spring Batch, if a batch fails and the job is restarted, it runs from the point of failure, not from the beginning.

Also, to prevent duplicate runs, a batch that has already succeeded throws an exception if you run it again with the same parameters.
