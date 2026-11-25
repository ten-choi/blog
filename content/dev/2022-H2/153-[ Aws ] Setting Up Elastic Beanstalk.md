---
title: "[ Aws ] Setting Up Elastic Beanstalk"
labels: ["Cloud","elastic","AWS","eb","Archive"]
published: true
date: 2022-12-28T15:37:50+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 153
tistoryUrl: "https://yeolceo.tistory.com/153"
tistoryCategory: "Cloud"
tistoryTags: ["elastic","AWS","eb","aws"]
tistoryPostedAt: "2022-12-28 15:37:50"
language: en
bloggerPostId: "276661303823342500"
---
#### ? **Environment** 

Python 3.8  
Aws Platform

#### ? **Overview**

Let's set up Elastic Beanstalk on AWS.

#### ? **Contents**

-   What is EB
-   How to create EB

## **\- What Is EB**

EB (Elastic Beanstalk) is an orchestration service from AWS that makes it easier to manage servers.   
Key features  
\- Manage deployment settings and deploy quickly with the EB CLI  
\- More efficient management of server infrastructure, logs, monitoring, and provisioning of capacity or cost

## **\- How to Create EB**

Search for EB in the AWS search bar.  
Click Applications at the top of the left menu.  
Create a new application with the button on the right.  

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img.webp)

We'll set up environments under the application.  
Pick a name that fits the project you're building and your EB setup.  
Keep the description short.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_1.webp)

Create a new environment in the application you just made.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_2.webp)

Use a web server environment.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_3.webp)

Name the environment with the parent application's name in mind.  
If you want the domain to mean something specific, fill that in too.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_4.webp)

This post is based on a Python Django server,  
so choose Python as the platform.  
It's a good idea to match the platform branch's Python version to the one you develop with.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_5.webp)

Make sure you click Configure more options to set up EB in detail!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_6.webp)

## **\- Configuring More EB Options**

Avoid a single instance so you can use load balancing, auto scaling, and so on.  
Choose Custom configuration so you can customize it.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_7.webp)

Under Software, configure logging for what happens on the instances.  
It costs money, so only turn it on if you need it.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_8.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_9.webp)

Under Instances, apply a security group.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_10.webp)

I kept the defaults and just created a separate security group.  
[**Creating a security group**](https://yeolceo.tistory.com/150)    
You can create a security group under Network & Security in the EC2 section.  
Select the security group you created.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_11.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_12.webp)

Set auto scaling to fit your scale. I went with 2 instances.  
If you're just learning and want to keep costs down, 1 instance is fine.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_13.webp)

You can check instance specs via **Learn more**.  
I went with a **t4g.small** instance: 2 cores, 2 GB of memory.  
[AWS EC2 specs link](https://aws.amazon.com/ko/ec2/spot/instance-advisor/)  

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_14.webp)

Scaling triggers let you monitor the state of the environment.  
Measure by CPU and set the unit to percent.  
Set the upper and lower thresholds to match the unit.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_15.webp)

You need an HTTPS listener for distributing traffic through the load balancer.  
If you have an SSL certificate in AWS, add it to the listener.  
If not, skip this step.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_16.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_17.webp)

You can pick whatever deployment strategy you want, such as blue/green or rolling.  
I went with all at once, but if you want to try a deployment strategy, choose rolling and set the batch percentage accordingly.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_18.webp)

Under Security, create an EC2 key pair and apply it.  
[Creating an EC2 key pair](https://yeolceo.tistory.com/152)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/153/img_19.webp)

I don't use the remaining settings, so go ahead and create the EB environment.

**? Well-grounded advice is always welcome. Code with care.**
