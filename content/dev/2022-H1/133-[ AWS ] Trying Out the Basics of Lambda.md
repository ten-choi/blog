---
title: "[ AWS ] Trying Out the Basics of Lambda"
labels: ["Cloud","aws","lambda","Archive"]
published: true
date: 2022-05-27T17:37:31+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 133
tistoryUrl: "https://yeolceo.tistory.com/133"
tistoryCategory: "Cloud/aws"
tistoryTags: ["AWS","lambda","lambda"]
tistoryPostedAt: "2022-05-27 17:37:31"
language: en
bloggerPostId: "1856364444061249276"
---
#### Environment

Mac m1  
Aws Lambda  
NodeJS

#### Overview

A basic test: we'll go into AWS and use Lambda with the sample code.

#### Contents

-   What is Lambda
-   How to use Lambda

## **\- What Is Lambda**

It's a **serverless computing platform** provided by AWS.

You can **provision** functions or run them repeatedly whenever you want, without managing any servers. Users don't have the burden of managing servers and can just use functions easily.

Provisioning: allocating, placing, and deploying system resources to fit user needs, so they're ready to use immediately when needed.

Use cases  
- Running code on a schedule (e.g. setting up a cron to run code every minute)  
\- Running code from a trigger (e.g. a trigger that fires when a file is uploaded to S3)  

## **\- **Lambda** Basics**

First, log in to AWS and open the Console Home.

Search for Lambda and click it. You'll see a bunch of descriptions, and there's a Create function button in the right corner.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/133/img.webp)

When you create a function, you'll see the options below. Use **Blueprint**. As the description says, it's meant for testing with sample code, and the AWS documentation does the same thing.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/133/img_1.webp)

Type "hello" and the default samples show up. The first one is a Node environment and the one below is Python. The environment doesn't really matter for this post, but I'll test with Node.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/133/img_2.webp)

Just give the function a simple name and finish creating it with the default permissions. Scroll down and you'll find the Create button.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/133/img_3.webp)

Click the function you created. You'll see a screen like the one below. Let's create a test event.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/133/img_4.webp)

Enter an event name and save it without any other settings, and you'll see a test event has been created.  

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/133/img_5.webp)

Run the test as is, and you'll see the logs from the index.js file we set up at the start show up below.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/133/img_6.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/133/img_7.webp)

That was a quick Lambda test. Happy coding, and keep at it.
