---
title: "[ Aws ] How to Build a Bastion Host with EC2"
labels: ["Cloud","aws","EC2","BastionHost","Archive"]
published: true
date: 2023-06-15T18:50:36+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 177
tistoryUrl: "https://yeolceo.tistory.com/177"
tistoryCategory: "Cloud/aws"
tistoryTags: ["KR","EC2","aws","BastionHost"]
tistoryPostedAt: "2023-06-15 18:50:36"
language: en
bloggerPostId: "7071961182062745351"
---
### What Is a Bastion Host on AWS?

A bastion host is an instance that sits in a public network and can talk to a private network,

so you can reach instances in that private network that you can't access directly

If you put private instances or a DB in a private subnet, you can reach them from outside

by going through the bastion host over SSH, and that extra step improves security

### Create an Instance for the Bastion Host

For the VPC, pick the one you created earlier. Don't have a VPC? [How to create an AWS VPC](https://yeolceo.tistory.com/175)  
Put the instance in the VPC's public subnet and enable a public IP so you can reach it

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/177/img.webp)

When connecting, check the inbound rules of the VPC's security group

Add a rule that accepts all traffic, or if there's a specific IP you'll connect from, add just that

### Connecting to EC2 and Setting Up the PEM File for SSH

Once it's created as above, let's connect to the EC2 instance. We need to reach the private instance inside the VPC

We SSH in using the PEM file, the key pair used when creating the private instance

Let's upload the PEM file with the scp command

In my case, I had to fix the issue described at the link on the right. See that post -> [scp issue fix](https://yeolceo.tistory.com/176)

```shell
scp -i /path/key-pair-name.pem /path/my-file.txt ec2-user@instance-public-dns-name:path/
```

After applying that fix, run the scp command again. The upload finished

Now SSH into the private instance using its IP along with the PEM file

```shell
ssh -i /path/key-pair-name.pem instance-user-name@instance-public-dns-name
```

Up through the scp step, I'd been doing everything as the root user

But to access the private instance, you have to log in as ec2-user

Probably for permission reasons, logging in as root is blocked 

```routeros
Warning: Permanently added '10.0.142.98' (ED25519) to the list of known hosts.
Please login as the user "ec2-user" rather than the user "root".
```

Change the PEM file's permissions so ec2-user can use it too

```shell
chmod 755 <keyPair file>
```

Then try connecting to the private EC2 instance again

If the login succeeds, you're done

### Quick Recap of the Steps

From the terminal, connect to the EC2 instance over SSH using the PEM file

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/177/img_1.webp)

You should be connected as shown below

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/177/img_2.webp)

Move to usr/pem, where you placed the PEM file beforehand

Try SSH with the PEM file one more time

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/177/img_3.webp)

If it connects, the process is complete
