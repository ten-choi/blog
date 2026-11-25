---
title: "Setting Up and Using Load Balancing on Azure"
labels: ["Cloud","azure","Archive"]
published: true
date: 2022-01-18T15:39:40+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 120
tistoryUrl: "https://yeolceo.tistory.com/120"
tistoryCategory: "Cloud/azure"
tistoryTags: ["azure","azure","azure","azure","azure"]
tistoryPostedAt: "2022-01-18 15:39:40"
language: en
bloggerPostId: "5426543312731654259"
retitled: true
---
#### Environment 

Azure Cloud  
Linux (Red Hat or CentOS)  
Standard A1 v2 (1 vCPU, 2 GiB memory)

#### Overview

We'll run an LB test with two servers using Azure's features.  
\-> I'll call load balancing "LB" for short.

#### Contents

-   Creating a resource group
-   Creating a virtual network
-   Creating a load balancer
-   Creating two VMs for LB
-   Setting up httpd on each server
-   LB test

## **\- Creating a Resource Group**

A resource group is a container that holds related Azure resources. Every resource for this test will go into the group we create here.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/120/img.webp)

Click Create and you'll get the Create resource group screen shown below.

Give the resource group whatever name you like.

I work around Seoul, so I set the region to Korea Central.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/120/img_1.webp)

Click Create right away and the resource group is done.

I didn't need tags, so I skipped them and went straight to Create.

## **\- Creating a Virtual Network**

We've built the big frame, the resource group. Now we need a network to use inside it.

Click Create virtual network.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/120/img_2.webp)

I used the resource group created earlier and gave it a similar name.

Since it's a Virtual Network, I ended the name with vNet.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/120/img_3.webp)

Since this is just for testing LB, create the virtual network with only the default settings above.

## **\- Creating a Load Balancer**

Just like before, find the Create button for the load balancer and click it.

Then select the resource group and enter a name for the new load balancer.

Leave the default settings as they are and set whatever name you like.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/120/img_4.webp)

**1\. Create the load balancer's public IP**

Once you're in the Frontend IP configuration section, you need to specify the public IP the load balancer will use.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/120/img_5.webp)

This is where you set the public IP used to reach the servers when clustering and LB are in action. 

The user on the far left of the diagram reaches the servers through the virtual public IP in the middle.

That public IP in the middle is the frontend public IP we're creating now.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/120/img_6.webp)

**2\. Add a backend pool**

When using existing virtual machines and virtual machine scale sets, you configure the backend pool through NICs.  
(NIC stands for network interface controller.)

Put simply, the backend pool creates a slot for the servers that will share the load.

Once you actually create virtual machines and add them to the backend pool, they're linked directly.

Give it whatever name you like and create it.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/120/img_7.webp)

Now create the load balancer. After it's created, click on it and you'll see something like the image below. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/120/img_8.webp)

**2\. Create a health probe**

Click the Health probes section and add one.

When you use load-balancing rules in Azure Load Balancer, you have to specify a health probe so the load balancer can detect the status of backend endpoints.

As the names in the image below show, these settings define the port to probe, how often to probe, and how many consecutive failures it takes to mark a server unhealthy and route to another server.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/120/img_9.webp)

**3\. Create a load-balancing rule**

Create a load-balancing rule in Azure Load Balancer. Set the public IP and backend pool the rule applies to.

The port is the one tied to the frontend IP that distributes traffic according to the load-balancing rule.

Likewise, set the backend port that receives the traffic, and apply the health probe you created.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/120/img_10.webp)

## **\- Creating Two VMs for LB** 

**1\. Create two VMs**

Now create the two virtual machines to test with. Go to Virtual machines and click Create.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/120/img_11.webp)

After finishing the basic VM settings, go to the Networking tab.

Check the option at the bottom to place the VM behind a load balancer.

Select the load balancer and backend pool you created. 

This lets traffic coming in on the load balancer's public IP reach the backend pool.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/120/img_12.webp)

 Once that's set, create the VM.

**2\. Add an inbound rule to each VM**

You need to allow an inbound rule for port 80, which we'll connect to.

Allow access on 80 so you can reach the VM when testing from outside.

### **\- Setting Up httpd on Each Server**

 Update yum and install httpd for testing the servers. Start the service with systemctl.

Use echo to create an index.html file in httpd's default web directory. Enter the commands below.

Set the HTML content to 01 and 02 respectively so it's easy to tell them apart later. 

```html
# sudo yum update -y
# sudo yum install httpd -y
# sudo systemctl start httpd
# cd /var/www/html
# echo "<html><h1>YEOL Server01</h1></html>" > index.html
```

 Just as you allowed access in the Azure inbound rules, you also need to allow it in the firewall. Enter these commands.

```html
# sudo firewall-cmd --permanent --zone=public --add-port=80/tcp
# sudo firewall-cmd --reload
```

 Check that each VM is reachable through its public IP. If both VMs are set up and reachable, you're ready.

### **LB Test**

On the Azure portal, go to the Load balancers section and click Frontend IP configuration. There you'll find the reachable public IP address. Open that IP in a browser. If it loads, keep hitting refresh. It isn't round robin, so it won't switch on every refresh.

If the httpd servers you made on VM1 and VM2 both show up through the load balancer's public IP, you're done.

Thanks for following along. Happy coding.
