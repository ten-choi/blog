---
title: "[ aws ] Configuring a VPC for Elastic Beanstalk"
labels: ["Cloud","aws","eb","VPC","Archive"]
published: true
date: 2023-06-15T19:18:22+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 178
tistoryUrl: "https://yeolceo.tistory.com/178"
tistoryCategory: "Cloud/aws"
tistoryTags: ["KR","eb","VPC","aws"]
tistoryPostedAt: "2023-06-15 19:18:22"
language: en
bloggerPostId: "688595466304122993"
---
Let's create an EB environment on AWS. Keep the initial settings as-is for the first part  
In the VPC section, select the VPC you created earlier. If you don't have one, use the image below to understand the flow  
and refer to the linked post -> [Creating a VPC](https://yeolceo.tistory.com/175)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/178/img.webp)

In the screen below, assign the VPC's 2 private subnets  
Since they're private, disable public IP  

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/178/img_1.webp)

Set the security group and instance type to fit your situation  
Our existing EB environment ran at least 2 instances, so load balancing needs to be configured  
Set the visibility to Public

For EB's ALB, specify the public subnets used in the VPC above  
The sample has 2 of them, so specify both  
If you set up Route 53, requests will go through DNS and Route 53 will forward them to the ALB

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/178/img_2.webp)

Configure the rest to fit your use case. Then deploy your existing project to that EB environment  
If it works, you're done  
If you have Redis, Filebeat, etc. on external servers, either connect them so they can talk to the inside of the VPC,  
or if they're built inside AWS, recreate them in the VPC's private subnets
