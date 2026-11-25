---
title: "[ Ngrok ] A Service for Accessing Localhost from the Outside"
labels: ["ThirdParty","ETC","ngrok","Archive"]
published: true
date: 2023-08-03T13:50:20+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 184
tistoryUrl: "https://yeolceo.tistory.com/184"
tistoryCategory: "ThirdParty/ETC"
tistoryTags: ["KR","ngrok"]
tistoryPostedAt: "2023-08-03 13:50:20"
language: en
bloggerPostId: "8092792576624962973"
---
#### Environment

-   mac

### What Is Ngrok?

It's a **service** that hooks a domain up to your machine so **localhost can be reached from the outside**.

The free plan alone is plenty useful. Here's the [download link](https://ngrok.com/download) if you want to grab it right away.

### How to Use It

You run it from the CLI with a command like this:

```bash
ngrok http 8000
```

If your server is running on port **8000**, you get an **https domain** that the outside world can use to reach that server.

With that domain you can receive things like **third-party callback APIs** that can't reach localhost.

And what if you're testing a frontend and **need to share your screen but don't have a separate server**?

**Letting people in through ngrok** works nicely for that too.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/184/img.webp)

Once it's running as above, hand the **forwarding URL** to someone outside or use it yourself.

It comes in handy more often than you'd think, so it's worth remembering.
