---
title: "[ aws ] How to Create Redis (ElastiCache)"
labels: ["Cloud","aws","VPC","redis","ElastiCache","Archive"]
published: true
date: 2023-06-15T14:16:45+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 174
tistoryUrl: "https://yeolceo.tistory.com/174"
tistoryCategory: "Cloud/aws"
tistoryTags: ["KR","VPC","redis","ElastiCache"]
tistoryPostedAt: "2023-06-15 14:16:45"
language: en
bloggerPostId: "6252446134136031094"
---
Redis is an in-memory DB. On AWS it goes by the name ElastiCache  
Let's search for ElastiCache in the AWS console and create a Redis cluster

![](https://blog.kakaocdn.net/dn/v1nWH/btsj5wdZ16l/SoFMFQYdvF71UAaIKJjoqk/img.png)

Read through the default settings and go along with them. You only need to change a few depending on your use case  
Whether to enable cluster mode depends on how much performance you need  
I plan to use Redis to store refresh tokens  
That doesn't need high performance, so I'll disable it and move on

Choose the node type with cost in mind. [AWS Redis pricing](https://aws.amazon.com/ko/elasticache/pricing/)  
Here's an example for when you're using a VPC  
The server will live on an instance in the private subnet (of public and private)  
So create Redis in the private subnet as well, so they can talk to each other

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/174/img.webp)

Just think things through up to the security group  
Most of the rest won't stray far from the defaults
