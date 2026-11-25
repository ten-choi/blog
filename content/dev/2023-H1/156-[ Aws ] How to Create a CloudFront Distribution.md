---
title: "[ Aws ] How to Create a CloudFront Distribution"
labels: ["Cloud","Cloudfront","Archive"]
published: true
date: 2023-01-02T17:38:22+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 156
tistoryUrl: "https://yeolceo.tistory.com/156"
tistoryCategory: "Cloud"
tistoryTags: ["Cloudfront","cloudfront","cloudfront"]
tistoryPostedAt: "2023-01-02 17:38:22"
language: en
bloggerPostId: "5905370667818162598"
---
#### ? **Environment** 

Aws platform

#### ? **Overview**

Deploying a frontend on AWS with CloudFront

#### ? **Contents**

-   What is CloudFront
-   How to create CloudFront
-   Error response pages

## **\- What Is CloudFront** 

It's an AWS web service that helps deliver static and dynamic web content quickly.  
Content is served through a worldwide network of data centers called edge locations.  
Requests are routed to the location with the lowest latency.

## **\- How to Create CloudFront**

Search for CloudFront in the AWS search bar.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/156/img.webp)

[How to create S3](https://yeolceo.tistory.com/155)  
Set the origin domain to the domain of the S3 bucket where your frontend build files are uploaded.   
Use public access for the S3 bucket.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/156/img_1.webp)

Set the viewer protocol policy to Redirect HTTP to HTTPS so users connect over HTTPS.  
For security, allow only GET and HEAD requests to CloudFront.  
Leave the cache policy at the default.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/156/img_2.webp)

[How to create an HTTPS domain with an SSL certificate](https://yeolceo.tistory.com/154)  
If you don't have an HTTPS domain yet, follow the guide above, setting the region to N. Virginia.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/156/img_3.webp)

Click the Add item button under Alternate domain name (CNAME).  
Enter the same HTTPS domain you want to use for CloudFront, e.g.) test.test.com  
If you have a separate alternate domain, enter that instead.  
Then apply the SSL certificate you created to the domain.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/156/img_4.webp)

Set the default root object to index.html.  
This is the path to index.html in the frontend build files on S3.   
Create the distribution.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/156/img_5.webp)

## **\- Error Response Pages**

Click the CloudFront distribution you created.  
On the Error pages tab, click the button on the right.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/156/스크린샷 2023-01-02 오전 11.48.38.webp)

Handle 403 and 404 errors as shown in the image below.  
This sets the response page path for when something goes wrong. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/156/img_6.webp)

Now the site loads without any issues.

**? Well-grounded advice is always welcome. Code with care.**
