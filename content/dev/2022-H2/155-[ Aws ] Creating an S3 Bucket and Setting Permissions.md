---
title: "[ Aws ] Creating an S3 Bucket and Setting Permissions"
labels: ["Cloud","aws","s3","Archive"]
published: true
date: 2022-12-30T13:26:52+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 155
tistoryUrl: "https://yeolceo.tistory.com/155"
tistoryCategory: "Cloud/aws"
tistoryTags: ["AWS","s3","s3"]
tistoryPostedAt: "2022-12-30 13:26:52"
language: en
bloggerPostId: "2638327577349467911"
---
#### ? **Environment** 

Aws platform

#### ? **Overview**

Create an S3 bucket on AWS and set its permissions

#### ? **Contents**

-   What is S3
-   How to create S3

## **\- What Is S3** 

S3 (Simple Storage Service) is an object storage service that offers scalability, data availability, security, and performance.  
You can store all kinds of data, manage access, and log and monitor your storage.

I've split permission management into three broad types. I'll explain each as we go.  
\- Public Access  
\- ACL (Access Control List)  
\- Bucket Policy

## **\- How to Create S3**

Search for S3 in the AWS search bar.  
Click the Create bucket button.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/155/img.webp)

Enter a bucket name that fits its purpose.  
If you're developing for users in Korea, the region should of course be Seoul.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/155/img_1.webp)

ACL  
Grants read/write permissions on objects and buckets to parties other than the bucket owner (other AWS accounts),   
such as all users or the authenticated users group.  
Enable ACLs to allow public access.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/155/img_2.webp)

Public Access  
This setting controls access for all outside users.

Set it so everyone can access the bucket.  
For security, avoid uploading files that shouldn't be public. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/155/img_3.webp)

Leave everything else at the defaults.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/155/img_4.webp)

Upload a file to check that it works.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/155/img_5.webp)

Click the Upload button and upload a regular file.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/155/img_6.webp)

Click the uploaded object and open its URL in a browser.

![](https://blog.kakaocdn.net/dn/bzBzI4/btrUTX2xtmO/ndyxREYFFE1zXiWpEhmoK0/img.png)

You'll get an access denied error like the one below.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/155/img_7.webp)

Bucket Policy  
A bucket policy lets you define the scope of who has which permissions.  
It gives you more fine-grained access control than ACLs.

Click the Edit button at the bottom right of the image.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/155/img_8.webp)

Copy the bucket ARN on the left.  
Click Policy generator on the right.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/155/img_9.webp)

You can generate a policy on the page below.  
Select Policy: S3 Bucket Policy  
principal: \*  
Action: GetObject  
ARN: paste the S3 ARN you just copied

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/155/img_10.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/155/img_11.webp)

Starting with the Add Statement button, click through the buttons as they appear.  
Copy the generated bucket policy in JSON format.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/155/img_12.webp)

Go back to the previous page and paste in the policy you copied.  
**You must append /\* to the value of the Resource key in the policy.  
**It means anything under the bucket's root path can be accessed.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/155/img_13.webp)

Set the ACL so all users can read, as shown below.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/155/img_14.webp)

Then click the uploaded image and check that it works.

**? Well-grounded advice is always welcome. Code with care.**
