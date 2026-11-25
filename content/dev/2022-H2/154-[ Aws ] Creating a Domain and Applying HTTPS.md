---
title: "[ Aws ] Creating a Domain and Applying HTTPS"
labels: ["Cloud","route53","aws","Archive"]
published: true
date: 2022-12-29T13:13:13+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 154
tistoryUrl: "https://yeolceo.tistory.com/154"
tistoryCategory: "Cloud"
tistoryTags: ["route53","aws","aws","aws","aws"]
tistoryPostedAt: "2022-12-29 13:13:13"
language: en
bloggerPostId: "9051975699470968638"
---
#### ? **Environment** 

Aws platform

#### ? **Overview**

Registering a domain on AWS and applying HTTPS

#### ? **Contents**

-   What is Route53
-   How to create
-   How to apply HTTPS

## **1\. What Is Route53** 

It's the DNS (Domain Name System) service provided by AWS.  
DNS is what lets you use a domain name in place of an IP address.  
e.g.) 0.0.0.0 -> test.co.kr

## **2\. How to Create**

Search for Route53 in AWS.  
Select Hosted zones at the top of the left menu.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/154/img.webp)

Create the name you'll use for hosting.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/154/img_1.webp)

Enter the domain name and create the hosted zone.  
If you enter test.com as the zone's domain name,  
every domain you create in that zone will share the same suffix: xxxx.test.com.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/154/img_2.webp)

Create a record in the hosted zone.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/154/img_3.webp)

The domain you set on the zone is appended after the record's name.  
In my case, I used a hosted zone that already existed.

Enter a name and use the IPv4 (A) record type.  
Use the Alias feature to point it at the AWS server you want to route to.  

For EB or EC2, set the routing target and region correctly, then pick the matching domain.  
For CloudFront, set the routing target and region correctly, then enter the distribution's domain name.  
Create the record.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/154/img_4.webp)

Now you can reach the selected server via the domain you just entered.

## **3\. How to Apply HTTPS** 

To use HTTPS, you need to complete SSL certification.   
Search for Certificate Manager in AWS.  
Select List certificates at the top left, then click Request at the top right.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/154/img_5.webp)

Enter the same domain you'll use in the hosted zone.  
If you want to create **subdomains** under the hosted zone, put a \* (asterisk) at the very front.  
**Covering subdomains too, e.g.) \*.test.co.kr  
**Then SSL will apply even if you create domains in Route53 like the example below.   
****Subdomain e.g.) test1.test.co.kr**  
**

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/154/img_6.webp)

Apart from the domain name, leave the other settings at the recommended defaults.  
Once it's created, the status will show Pending validation, as below.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/154/img_7.webp)

Click the certificate you created.  
Under Domains, click the **Create records in Route53** button.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/154/img_8.webp)

Create the CNAME record.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/154/img_9.webp)

This adds a CNAME record in Route53.  
Shortly after the record is created, SSL validation completes.

**? Well-grounded advice is always welcome. Code with care.**
