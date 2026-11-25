---
title: "An Auto-Upgrade Issue in AWS RDS"
labels: ["aws rds","trouble shooting","Archive"]
published: true
date: 2023-06-01T10:00:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "8494709000801029814"
source: "blogger"
sourceBlog: "https://ten-logged.blogspot.com/"
sourcePostId: "3221506798590588833"
sourceStatus: LIVE
sourceUrl: "https://ten-logged.blogspot.com/2023/06/aws-rds.html"
sourcePublishedAt: "2023-06-01T21:49:00-07:00"
---
**Topic: Troubleshooting for Amazon RDS auto minor update**

We ran into an issue while using AWS RDS  
Let's document it

1\. Defining the problem  
The server started throwing the error below

```
Cannot execute statement in a READ ONLY transaction.
Error: Cannot execute statement in a READ ONLY transaction.
```

2\. Finding the cause  
In the AWS RDS settings, "Enable auto minor version upgrade" was checked  
The time in the upgrade scheduler matched the time the errors started  

The RDS cluster had 3 instances in total:  
1 writer and 2 readers  
  
Here's the likely scenario  
At the scheduled time, each instance across the RDS cluster gets updated  
The logs show the writer DB hit an out-of-memory error  
While the writer instance reboots, there's no instance that can write  
A reader instance is given the writer role  
The restarted instance is given the reader role to keep the ratio  
The problem was the endpoint the server used to call the DB  
It was using an instance endpoint, not the RDS cluster's writer endpoint  
If you use the cluster's writer and reader endpoints, role changes aren't a problem  
because the cluster routes them for you  
But we were using the instance endpoint  
And the restarted instance now had the reader role  
So the server ended up sending writes to an instance that was now a reader  
That's why we got the error above

3\. Fixing and verifying  
I changed it to use the writer endpoint assigned to the cluster  
The reader was already correctly set to the cluster endpoint  
That's the standard way, so the writer endpoint must have been set wrong at some point  
The cluster also seems to handle load balancing automatically by role

The server uses ELB  
Change the writer instance endpoint in that ELB's env to the cluster endpoint  

4\. Deploying  
Change the environment variable in env and save  
The server instance then restarts on its own and picks up the change
