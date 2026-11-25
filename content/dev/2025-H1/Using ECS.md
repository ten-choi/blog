---
title: "Using ECS"
labels: ["Archive"]
published: true
date: 2025-03-23T11:17:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "8666078105078486746"
source: "archive"
archivePath: "_archive/dev/infra/containers/use aws ecs.md"
---

spec
our platform's DAU is estimated at 1 million
our platform has a lot of projects: 70


i'm going to move from java jdk8 to kotlin jdk17


we used tomcat and apache on linux

so we had a meeting and we're going to choose docker and aws ecs

at this company we can't control aws, not even the dev environment, let alone production


we had 4 meetings

how do we move to docker
how long will it take
is it better on cost than before

we picked the biggest project among the 70 projects as the first one
i created a draw.io diagram to communicate.

aws ecs fargate and ecs both exist

when i looked at aws re:Post, based on the cost analysis of ecs deployment options:

ecs on ec2 is generally much cheaper than fargate.
Fargate would be more expensive since it charges separately for vCPU and memory usage, while EC2 offers combined resource pricing.


and the final change: when i run the docker image for the kotlin server we need a spring boot profile
so we wrote the env profile in the task definition


