---
title: "Setting a Static IP on CentOS 7, the Simple Way"
labels: ["OS","Linux","centos7","centos","Archive"]
published: true
date: 2021-01-12T18:02:37+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 75
tistoryUrl: "https://yeolceo.tistory.com/75"
tistoryCategory: "OS/Linux"
tistoryTags: ["centos7","centos7","centos7","centos7","centos"]
tistoryPostedAt: "2021-01-12 18:02:37"
language: en
bloggerPostId: "2495088314521386285"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/75/img.webp)

### **\- How to Set a Static IP on CentOS 7**

First, start **CentOS 7** and open a terminal. Switch to the **root** account with the su - command.

(You need the permissions to edit the network configuration file.)

```html
$ su -
```

![Enter whatever password you remember~](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/75/img_1.webp)

The path below is the network configuration file. Open it with the text editor (vi).

(If the file name is slightly different, find it in that directory and open it.)

```html
$ vi /etc/sysconfig/network-scripts/ifcfg-ens33
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/75/img_2.webp)

#### **Changing the File Settings**

Once you run the command, you'll see something like this:

```html
TYPE="Ethernet"
PROXY_METHOD="none"
BROWSER_ONLY="no"
BOOTPROTO="dhcp"
DEFROUTE="yes"
IPV4_FAILURE_FATAL="no"
IPV6INIT="yes"
IPV6_AUTOCONF="yes"
IPV6_DEFROUTE="yes"
IPV6_FAILURE_FATAL="no"
IPV6_ADDR_GEN_MODE="stable-privacy"
NAME="ens33"
UUID="5c1140e4-f15f-4a78-9bd9-c02f371d720a"
DEVICE="ens33"
ONBOOT="yes"
```

Copy and paste the code below; I've added explanations underneath.

```html
TYPE="Ethernet"
PROXY_METHOD="none"
BROWSER_ONLY="no"
#BOOTPROTO="dhcp"                
DEFROUTE="yes"
IPV4_FAILURE_FATAL="no"
IPV6INIT="yes"
IPV6_AUTOCONF="yes"
IPV6_DEFROUTE="yes"
IPV6_FAILURE_FATAL="no"
IPV6_ADDR_GEN_MODE="stable-privacy"
NAME="ens33"
UUID="5c1140e4-f15f-4a78-9bd9-c02f371d720a"
DEVICE="ens33"
ONBOOT="yes"

# this code is for static IP   
BOOTPROTO="none"
IPADDR=192.168.219.144
PREFIX=24
GATEWAY=192.168.219.1
DNS1=168.126.63.1
DNS2=168.126.63.2
ONBOOT="yes"
PEERDNS=no
```

#### **What Changed**

1\. Above the lines you add, leave a comment (using #) noting what you added.

2\. With BOOTPROTO set to dhcp, the IP is assigned dynamically, so comment out the existing line and set it to none instead.

3\. For IPADDR, if CentOS 7 currently has internet access, use the same address as your current IP and change only the last number to whatever you want.

4\. PREFIX: when using a static IP, you need to specify either a prefix or a netmask.

5\. GATEWAY: if you're behind a wireless router, it's almost always the first three octets of your IP plus 1 as the last number.

6\. DNS1 and DNS2 are the primary and secondary DNS servers; the DNS IPs I used are KT's servers.

7\. ONBOOT asks whether to apply this configuration at boot — set it to **yes**.

8\. PEERDNS controls whether to accept certain information from **DHCP**. Since we set BOOTPROTO to **none**, turn it off.

Save with the command below. (Type a colon, then wq.)

```html
:wq
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/75/img_3.webp)

You need to restart the network for the new IP to take effect.

```html
systemctl restart network
```

 Check your IP with the **ip addr** command. All good? That's how to set a static IP on **CentOS 7**.

I hope it went smoothly. Happy coding!
