---
title: "Getting Started with AWS EC2 - Straight to a Running Instance"
labels: ["Cloud","AWS","Archive"]
published: true
date: 2021-02-17T18:13:15+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 87
tistoryUrl: "https://yeolceo.tistory.com/87"
tistoryCategory: "Cloud"
tistoryTags: ["AWS","aws","aws"]
tistoryPostedAt: "2021-02-17 18:13:15"
language: en
bloggerPostId: "452258267239676622"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/aws.webp)

### **\-Everyone's Using AWS, So I'm Trying It Too**

Search for **AWS** and go to the site.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img.webp)

Sign up for an account.

**AWS** is a **paid service**, so you'll need a card to register, like a **debit or credit card**.

We're planning to stick to the **Free Tier**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_1.webp)

After you create the account, it takes a little while to **activate**!

See the **red line** on the right side of the image below? **Set the region to Seoul up front**.

(If you create things in some unfamiliar region, keep using those resources, then casually switch to Seoul and create more, you can run into problems..)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_2.webp)

Select **Asia Pacific (Seoul)**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_3.webp)

Then open Services and pick **EC2** under Compute.

(**Elastic Compute** => computing where you can elastically scale the resources you use)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_4.webp)

The first time you open the dashboard you'll see a screen like the one below. Click **Launch instance** at the very bottom. I already have one in use,

so one instance is running.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_5.webp)

We'll run the server on **Ubuntu 18 LTS**. Click Select, underlined in red.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_6.webp)

Being Free Tier, it's 1 CPU and 1 GB of memory, but it doesn't really feel that limited. Since the goal is learning, choose the Free Tier option and click **Review and Launch**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_7.webp)

Leave the default options as they are and click **Launch**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_8.webp)

You need a key to access EC2. Create a new key pair.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_9.webp)

Give the **key pair a name** of your choice, then **download the key pair**. Make sure you save it **somewhere you'll remember**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_10.webp)

Now when you **launch the instance**, you'll see a "pending" message. After a little while, check your running instances.

It'll show as running.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_11.webp)

Click the **instance** we created, and the **Connect** button becomes active.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_12.webp)

**Almost there!!** To connect to the Ubuntu instance we created, we need to use **ssh**.

First, click SSH client in the menu. Instructions for connecting appear at the bottom.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/화면 캡처 2021-02-16 160910.webp)

Now we need to connect to the **instance** from our own computer via ssh. Open a **Command Prompt**.

Be sure to run it **as administrator**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_13.webp)

We saved the key pair a moment ago. Copy the path where you saved it.

Then move to that path in cmd.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_14.webp)

#### \-There Are Two Things to Do-

**Set permissions on the key pair** and **connect to the AWS Ubuntu server over ssh**.

Let's look at the key pair first. The key pair must not be publicly viewable, so we need to **set its permissions**.

But since we're not on Linux, we can't easily use the chmod command shown there. So we have to **set it manually**.

1\. Open Properties, go to the **Security** tab, and click **Advanced**

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_21.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_22.webp)

What we're doing is restricting permissions. The file must not inherit permissions from its parent, otherwise it can be used from elsewhere.

After that, we allow only administrators so only they can use it.

To stop permission inheritance, click **Disable inheritance**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_15.webp)

Choose to convert them to explicit permissions. Don't remove them all.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_16.webp)

To allow only administrators, remove every principal except **SYSTEM** and **Administrators**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_17.webp)

That takes care of the chmod part. Now go back to the Command Prompt.

Enter your own **ssh** command below. (It's the one starting with ssh -i at the very bottom of the image below)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/화면 캡처 2021-02-16 160910_1.webp)

Copy and paste it at that path.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_18.webp)

If it went through, great.

If you get **permission denied** like below, don't panic. Check that the **name of the key pair you downloaded** matches the name in the command,

or, if you didn't run it as administrator, **run it as administrator**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_19.webp)

If you see something like below, your Linux server is ready to use : - )

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_20.webp)

That was a no-fuss walkthrough of EC2, just up to getting it running. Happy, diligent coding.
