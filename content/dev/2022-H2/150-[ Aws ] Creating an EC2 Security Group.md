---
title: "[ Aws ] Creating an EC2 Security Group"
labels: ["Cloud","aws","Archive"]
published: true
date: 2022-12-12T18:48:27+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 150
tistoryUrl: "https://yeolceo.tistory.com/150"
tistoryCategory: "Cloud"
tistoryTags: ["aws","AWS","aws","aws"]
tistoryPostedAt: "2022-12-12 18:48:27"
language: en
bloggerPostId: "4460745441848732029"
---
#### ? **Environment** 

Aws web

#### ? **Overview**

Let's set up a security group for EC2!

#### ? **Contents**

-   Creating a security group

What's a security group? It's an EC2 feature in AWS that improves security by restricting inbound and outbound traffic  
to your EC2 instances by IP and port.

## **\- Creating a Security Group**

Search for EC2.  
Select Security Groups from the menu.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/150/img.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/150/img_1.webp)

Create a security group.  

Keep the name and description short.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/150/img_2.webp)

Inbound rules are the IPs and ports allowed to connect to EC2 from outside. I'll be connecting over HTTP and HTTPS, so I opened 80 and 443.  
If that's not your case, pick something like Custom TCP under Type.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/150/img_3.webp)

I left outbound traffic (from the inside out) unrestricted.  
This is a case where no particular restriction is needed for security.   
Likewise, if you do need it, restrict outbound traffic to specific destination IPs and ports.  
Click the Create security group button.

Now you can use this security group whenever you need it.  

Finally, the Name column shows up empty, so you have to set it separately.  
Give the security group you just created a name.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/150/img_4.webp)

**? Well-grounded advice is always welcome. Code with care.**
