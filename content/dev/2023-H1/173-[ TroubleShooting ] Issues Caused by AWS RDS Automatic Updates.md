---
title: "[ TroubleShooting ] Issues Caused by AWS RDS Automatic Updates"
labels: ["TroubleShooting","Aws","RDS","Archive"]
published: true
date: 2023-06-02T13:50:00+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 173
tistoryUrl: "https://yeolceo.tistory.com/173"
tistoryCategory: "TroubleShooting/Aws"
tistoryTags: ["TroubleShooting","KR","aws","RDS"]
tistoryPostedAt: "2023-06-02 13:50:00"
language: en
bloggerPostId: "5852300009282878604"
---
We ran into an issue while using AWS RDS  
Let's document it

1\. Defining the problem  
The server started throwing the error below

```smali
Cannot execute statement in a READ ONLY transaction.
Error: Cannot execute statement in a READ ONLY transaction.
```

2\. Finding the cause  
In the AWS RDS settings, "Automatic Minor Version Upgrades" was checked  
The time in the upgrade scheduler matched the time the errors started  
The RDS cluster had 3 instances in total: 1 writer and 2 readers

Here's the likely scenario  
At the scheduled time, each instance across the RDS cluster was updated  
The logs confirmed the writer DB hit an out-of-memory error  
While the writer instance rebooted, there was no instance that could write,  
so the cluster would assign the writer role to a reader instance on its own  
The restarted instance is then given the reader role to keep the ratio  
The problem was the endpoint the server used to call the DB  
The server using RDS was pointed at an instance endpoint, not the RDS cluster's writer endpoint  
If you use the cluster's writer and reader endpoints, role changes aren't a problem, because the cluster routes them for you

But we were using the instance endpoint  
And the restarted instance now had the reader role  
So the server ended up sending writes to an instance that was now a reader  
That instance has no write permission, which produces the error above

3\. Fixing and verifying  
I changed it to use the writer endpoint assigned to the cluster  
The reader was already correctly set to the cluster endpoint  
That's the standard way, so it looks like someone got the writer endpoint wrong during the initial setup  
The cluster also seems to act as a load balancer by role

The server runs on AWS EB (Elastic Beanstalk)  
Change the writer instance endpoint in the EB env to the cluster endpoint

4\. Deploying  
Change the environment variable in env and save  
The server instance then restarts on its own and picks up the change
