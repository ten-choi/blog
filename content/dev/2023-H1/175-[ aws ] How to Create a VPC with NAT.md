---
title: "[ aws ] How to Create a VPC with NAT"
labels: ["Cloud","aws","NAT","VPC","Archive"]
published: true
date: 2023-06-15T17:54:16+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 175
tistoryUrl: "https://yeolceo.tistory.com/175"
tistoryCategory: "Cloud/aws"
tistoryTags: ["NAT","KR","VPC","aws"]
tistoryPostedAt: "2023-06-15 17:54:16"
language: en
bloggerPostId: "9191858611251064085"
---
AWS VPC stands for Virtual Private Cloud  
It's an AWS service that gives you an isolated virtual network space  
The reason I'm introducing a VPC this time is NAT  
First, let's look at the VPC diagram to understand how data flows between internal instances and the outside

![from aws](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/175/img_8.webp)

![from aws](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/175/img_9.webp)

The fastest way to learn is to build one. Let's create an AWS VPC  
Find VPC in the AWS console and click the Create button. When you see the screen below, choose "VPC and more"  
I'll explain how to create it with "VPC only" separately at the bottom of the post. For now, go with "VPC and more"

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/175/img.webp)

The official docs recommend two or more AZs for higher availability  
Specify 2 AZs and set up one private and one public subnet per AZ  
Set up a NAT so that outbound requests all go out from a single IP  

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/175/img_1.webp)

If you create everything at once like above, the VPC setup is done. To understand the internals, let's create the VPC on its own  
In IPv4 CIDR, specify the subnet range the VPC will use  
Leave everything else at the defaults and finish  

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/175/img_2.webp)

Now let's create the subnets the VPC will use. Specify availability zones (AZs) a and b to create 2  
Two or more is said to be better for high availability  
Create one public and one private subnet in each of a and b, for 4 subnets in total  
Enter the IPv4 CIDR range based on how many IPs each subnet needs

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/175/img_3.webp)

This VPC needs internet access  
Create an IGW, then click the Actions button on that IGW to attach it to the VPC  
As the description in the image below says, it's a virtual router that connects the VPC to the internet

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/175/img_4.webp)

The automatic setup created 3 route tables. 2 were for the NAT and 1 was for tying the public subnets to the IGW  
Let's create the public subnets' route table first

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/175/img_5.webp)

This is where you let the public subnets communicate with the outside through the IGW  
Use Edit routes to add the IGW you created earlier  
Set the IP to 0.0.0.0. That's because 0.0.0.0 means every IPv4 address on the machine  
In other words, it connects things so any host can reach it

In the Subnet associations tab, specify that the 2 public subnets use this table  
Now the public subnets are reachable from the internet  

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/175/img_10.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/175/img_11.webp)

Next we need a route table for the private subnets  
but first we need to create the NAT that will play the IGW's role in the private subnets' route table

NAT is one of the big reasons to use a VPC  
If you assign an EIP to the NAT, all outbound requests go out from the NAT's EIP  
If a company you work with uses an allowlist, sending everything out through one IP is the way to go

For example, say you're calling some Kakao server that only accepts pre-registered IPs  
Without NAT, auto scaling spins up new instances with unexpected IPs  
If an IP isn't registered, the calls fail and you've got a problem

The NAT lives in a public subnet. Instances in the private subnets  
can send data to the NAT through the route table  
and the NAT sends that data out through the IGW

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/175/img_6.webp)

Assign an EIP, set the connectivity type to Public, and finish  
Now you just need a route table that ties the NAT to the private subnets

The create-everything-at-once option makes 2 route tables for the private subnets  
It probably does that to cover cases like wanting separate route tables  
for internal and external traffic

If you're only using NAT, you can explicitly associate both subnets with one table, like the public subnets' route table  
Make 1 or 2, whichever fits your use case  
Just set the NAT where the IGW was and associate the subnets 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/175/img_7.webp)

And that's it for the VPC setup
