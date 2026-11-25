---
title: "[AWS] Creating an EC2 Instance and Logging In with SSH and a Password"
labels: ["Cloud","aws","ec2","Archive"]
published: true
date: 2022-02-17T12:37:19+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 123
tistoryUrl: "https://yeolceo.tistory.com/123"
tistoryCategory: "Cloud/aws"
tistoryTags: ["ec2","ec2","ec2"]
tistoryPostedAt: "2022-02-17 12:37:19"
language: en
bloggerPostId: "4187514660251497526"
---
#### Environment 

Windows 10  
Red Hat 8

#### Overview

Create a Red Hat instance with AWS EC2, set up an Elastic IP, and get logged in, all in one go.

#### Contents

-   **Creating an EC2 instance**
-   **Creating a new key pair**
-   **Setting key pair permissions for login**
-   **Login test 1**
-   **Switching SSH login from a PEM key to a password** 
-   **SSH login test 2**

## **\- Creating an EC2 Instance**

Find the EC2 service on the AWS site. Click the EC2 section and you'll see a Launch instance button. Click it to create an instance.

1\. Choose an AMI

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/123/img.webp)

You need to choose an Amazon Machine Image (AMI).

Pick whichever Linux you want; I'll go with Red Hat.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/123/img_1.webp)

2\. Choose an instance type

It says free tier eligible, but with 1 CPU and 1 GB of memory it's slow. Only use it for small-scale testing.

This is a server I'll keep using, so I picked an instance with 2 CPUs and 8 GB of memory.

3\. Configure the instance

Skip IP and network settings and go with the defaults.

4\. Add storage 

Reducing it below the default size throws an error, so there's probably a pricing-related policy behind it. Keep the default settings.

5\. Add tags

I don't add any tags.

6\. Configure the security group

This is where you set SSH login, which ports are open for inbound and outbound traffic, and which IPs can connect. You can change these later, so keep the default SSH login settings and move on.

7\. Review

Once all the settings are done, click Review and Launch. 

A dialog about creating a key pair pops up.

If it's your first time creating a key pair, I recommend creating one first following the steps below, rather than creating a new key pair right there.

Leave the current window open and create a new key pair in a new window.

## **\- Creating a New Key Pair**

Click Key Pairs in the menu and press the Create key pair button.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/123/img_2.webp)

Give it whatever name you like.

Choose RSA, the public-key algorithm. AWS stores the public key and gives you the private key file.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/123/img_3.webp)

Once created, the key pair is generated and a single pem file downloads.  
(You can only download this file once, so keep it safe.)

Go back to the last step of the instance setup, apply the key pair you just made, and finish creating the instance.

The instance is created! Now try logging in.

Open a cmd window and log in over SSH using the pem file.

```html
ssh -i D:\yourpath\my_key.pem  ec2-user@11.11.11.11
```

If you get a Permission denied error, you've made it right up to the point of logging in.

## **\- Setting Key Pair Permissions for Login**

If you don't set permissions on the pem file you just downloaded, you may get a permissions error. On Linux it's a quick chmod, but on Windows it's not that simple.

Right-click the key file, open Properties, and click the Security tab.

Click the Advanced button at the bottom.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/123/img_4.webp)

Click Disable inheritance and remove all permissions. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/123/img_5.webp)

Once everything is gone, you need to click Add to add one back.

Click Select a principal.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/123/img_6.webp)

Click Advanced.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/123/img_7.webp)

Click Find Now, then find and add your own PC user.

As shown below, the Read & execute and Read permissions must be granted for the pem file to be readable. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/123/img_8.webp)

If only one user remains, confirm and try logging in.

## **\- Login Test 1**

You need to log in by specifying the pem file, as below.

ec2-user is the default AWS user. 

We're logging in over SSH; the -i option specifies the location of the RSA key file, followed by its path.

Add username@server-IP and the login command is complete. 

```css
ssh -i D:\yourpath\my_key.pem  ec2-user@11.11.11.11
```

You're logged in.

## **\- Switching SSH Login from a PEM Key to a Password** 

```html
# sudo su
# passwd
```

You need to log in by specifying the pem file, as below. 

```html
# vi /etc/ssh/sshd_config
```

ec2-user is the default AWS user. 

```html
PermitRootLogin yes
PasswordAuthentication yes
```

We're logging in over SSH; the -i option specifies the location of the RSA key file, followed by its path.

```html
# service sshd restart
```

And that's it. 

## **\- Login Test 2**

You need to log in by specifying the pem file, as below. 

ec2-user is the default AWS user. 

We're logging in over SSH; the -i option specifies the location of the RSA key file, followed by its path.

Add username@server-IP and the login command is complete.

```css
ssh -i D:\yourpath\my_key.pem  ec2-user@11.11.11.11
```

And with that, logging in with a password is done too. 

A newly created instance has no firewall, so it'd be a good idea to set up the firewall as well. 

Happy coding.
