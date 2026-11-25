---
title: "Analyzing the API Gateway Pattern"
labels: ["api gateway pattern","architecture","Archive"]
published: true
date: 2023-05-04T10:00:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "4969095454872178128"
source: "blogger"
sourceBlog: "https://ten-logged.blogspot.com/"
sourcePostId: "6916614068378448970"
sourceStatus: LIVE
sourceUrl: "https://ten-logged.blogspot.com/2023/05/api-gateway-pattern.html"
sourcePublishedAt: "2023-05-04T22:51:00-07:00"
---
Let's analyze the API gateway pattern.  

It's a server that acts as an intermediary between clients and microservices.  
If one service runs on four servers, each server will have a different domain.  
For example, assume four servers (customer, order, delivery, and review) together back a single service.  
And assume there are two clients that can connect: web and mobile.  

Four types of analysis

1\. There are four servers, split by domain. But a client needs two or more kinds of data at once.  
The client has to call two or more APIs and combine the results, which adds complexity.  
\-> Have the gateway request the needed data from each domain server and return it to the client.  
Sometimes the delivery server needs to know which items were ordered in order to deliver them.  
If the delivery server asks the order server directly which order it is, that creates coupling.  
It means that when the order server goes down, the delivery server is directly affected too.

2\. Exposing domain servers' endpoints and calling them directly is bad for security.  
\-> With a gateway, you can hide the endpoints of the domain servers that call the data sources.

3\. Assume each domain manages its own logging.  
When an issue comes up, you might have to dig through the log files of all four domain servers to find it.  
\-> If the gateway manages logs, the gateway's log file alone tells you what the issue is.

4\. For routing policy, assume the global service has two regions: one in Korea and one in the US.  
Users in the US should be routed to the US server, based on their location determined via DNS.  
That's better for both performance and cost.  
But without a gateway, you'd have to set a routing policy on all four domain servers.  
\-> With a gateway, you can manage it from the gateway server's endpoint alone.

5\. I think it's a waste of resources if each domain server builds its own cache, four in total.  
\-> Use a gateway and keep the cache on a single server.  
That reduces load, improves performance, and returns more consistent data.  
  

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/archive/api-gateway-pattern-분석/img.webp)
