---
title: "CentOS 7 Firewall Commands, Explained"
labels: ["OS","Linux","centos7","Archive"]
published: true
date: 2021-01-25T18:35:09+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 78
tistoryUrl: "https://yeolceo.tistory.com/78"
tistoryCategory: "OS/Linux"
tistoryTags: ["centos7","centos7","centos7","centos7"]
tistoryPostedAt: "2021-01-25 18:35:09"
language: en
bloggerPostId: "8892064234724327494"
---
### **\- What Is a Firewall?**

A network security system that blocks connections coming from outside into the internal network, except from trusted, authorized networks.

**CentOS 7** ships with a firewall called **firewalld** by default. Its settings are applied

using **zones**. I'll use a **zone** named **public** as the example.

On **CentOS 7**, the firewall's default configuration is a **zone** named **public**,

located at /etc/firewalld/zones/public.xml.

So when you add settings to the **public** **zone**, they're saved to the **public.xml** file.

You can also keep a different set of settings in a **zone** with another name and use that.

### **\- Trying the Commands**

I've collected **commands** that come in handy when you need to manage the **firewall** on **CentOS 7**.

First, start **CentOS 7**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/78/img.webp)

Try entering the commands one by one as you follow the explanations below. (I ran them as **root**.)

**Check whether the firewall is running**

Prints **running** to the terminal if it's running, or **not running** if it's stopped.

```html
[YEOL@localhost]# firewall-cmd --state
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/78/img_1.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/78/img_2.webp)

**Stop the firewall**

This stops the whole firewall, so it's handy for figuring out whether a problem is caused by the firewall.

```html
[YEOL@localhost]# systemctl stop firewalld
```

**Start the firewall**

If you stopped the firewall, start it again.

```html
[YEOL@localhost]# systemctl start firewalld
```

**Apply firewall changes**

If you've changed the firewall settings, apply them with **reload**.

```html
[YEOL@localhost]# firewall-cmd --reload
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/78/img_3.webp)

**Settings applied at boot**

With **disable**, the firewall won't start even after a reboot. (Normally the firewall starts on reboot.)

```html
[YEOL@localhost]# systemctl disable firewalld
```

With **enable**, the firewall starts on reboot.

```html
[YEOL@localhost]# systemctl enable firewalld
```

**Add or remove allowed ports**

This means: **add** a port **permanently** to the **zone** named **public**. (Reading the English as you go makes it easier to understand.)

```html
[YEOL@localhost]# firewall-cmd --permanent --zone=public --add-port=3000/tcp

[YEOL@localhost]# firewall-cmd --permanent --zone=public --add-port=3000-6000/tcp // add a range
```

This means: **permanently** **remove** a port that was **added** to the **zone** named **public**.

```html
[YEOL@localhost]# firewall-cmd --permanent --zone=public --remove-port=3000/tcp

[YEOL@localhost]# firewall-cmd --permanent --zone=public --remove-port=3000-6000/tcp // remove a range
```

After changing settings, you need to run the **reload** command I explained above to apply them.

**Info for all firewall zones**

Shows the firewall's **interfaces, services, ports**, and other related info. Useful for checking your changes.

```html
[YEOL@localhost]# firewall-cmd --list-all
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/78/img_4.webp)

That was a quick tour of **CentOS 7** **firewall commands**. I hope it was easy to follow!

Happy coding!
