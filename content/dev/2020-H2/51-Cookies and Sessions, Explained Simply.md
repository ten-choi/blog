---
title: "Cookies and Sessions, Explained Simply"
labels: ["ETC","Data Communication","Cookies and Sessions","Cookie","Archive"]
published: true
date: 2020-10-06T10:16:54+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 51
tistoryUrl: "https://yeolceo.tistory.com/51"
tistoryCategory: "ETC/데이터 통신"
tistoryTags: ["쿠키와","쿠키","쿠키","쿠키"]
tistoryPostedAt: "2020-10-06 10:16:54"
language: en
bloggerPostId: "1436625735743634071"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/51/img.webp)

## \- First, About Communication

Let's say there's an HTTP server and a web client.

When the client makes a request through a REST API, the server handles it and returns a value.

If you think about that flow, you can see it's not a continuous connection; each exchange is a one-off.

Say the client asks to log in. Once the server processes it, the login is complete.

But the app has to keep proving that you're still logged in, while each exchange is one-off.

In other words, something has to verify you every time.

Going through the server every single time wastes resources, though, so I see cookies and sessions as existing to fill that gap

and keep information around. Caching is also about using resources efficiently. Take a look at the explanations below.

## \- Cookies

In a web environment, instead of the server repeatedly loading values every time data is requested,

it issues a data token, and the values are retrieved using that token. That token is called a cookie.

**In practice**

Having the server regularly load values from the DB takes up a fair amount of resources, so it issues the user

a cookie that holds the data. It's a way of offloading resources to the user to reduce the server's load.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/51/img-png.webp)

ex -> Issuing a JWT or cookie over HTTP and using it.

The image is a capture of cookies existing and being used on an ordinary website.

## \- Sessions

A session is a temporary store the server uses to keep certain values around.

**In practice**

Unlike cookies, it's not about loading DB values from the server; it's the server holding onto certain values as state.

Login info is a good example. The catch is that the more users you have, the heavier the load on the server.

As long as you use it without overloading the server, it's good for security.

ex -> When coding, just use sessions and the server manages that data.

The code below shows how to use sessionStorage in JS.

```html
sessionStorage.setItem("autosave", someValue );  //save to session
sessionStorage.getItem("autosave");  	     //read from session
```

## \- Cache

A cache is a file in the browser that stores data received from the server.

The goal is to speed up rendering by temporarily storing images or large resources that are likely to be reused.

**In practice**

The browser caches resources the user is likely to need again. Like cookies, it uses the resources of the user's computer.

Because cached data is used when a resource is reused, there's less data transfer, so re-rendering is faster.

ex -> An image that's been rendered once renders faster the next time.

Cookies vs. Sessions

<table style="border-collapse: collapse; width: 100%; height: 226px;" border="1" data-ke-style="style13"><tbody><tr style="height: 32px;"><td style="width: 17.0215%; height: 32px;">&nbsp;</td><td style="width: 40.1552%; height: 32px;">Cookie</td><td style="width: 42.8232%; height: 32px;">Session</td></tr><tr style="height: 32px;"><td style="width: 17.0215%; height: 32px;">&nbsp;Stored in</td><td style="width: 40.1552%; height: 32px;">Client</td><td style="width: 42.8232%; height: 32px;">Server</td></tr><tr style="height: 32px;"><td style="width: 17.0215%; height: 32px;">Size limit</td><td style="width: 40.1552%; height: 32px;">Max 4096 bytes each<br>Up to 20 per domain<br>(according to the browser standard)</td><td style="width: 42.8232%; height: 32px;">Unlimited, as far as the server allows</td></tr><tr style="height: 32px;"><td style="width: 17.0215%; height: 32px;">Speed</td><td style="width: 40.1552%; height: 32px;"><span style="color: #333333;">Data is on the user's PC, so it loads quickly<br>Slightly faster than sessions</span></td><td style="width: 42.8232%; height: 32px;"><span style="color: #333333;">Requires communication with the server,&nbsp;&nbsp;<br></span>so slightly slower than cookies</td></tr><tr><td style="width: 17.0215%;"><span style="color: #333333;">Security</span></td><td style="width: 40.1552%;">Stored on the user's PC, so somewhat less secure</td><td style="width: 42.8232%;">Data is managed on the server, so it's<br>relatively secure</td></tr><tr style="height: 32px;"><td style="width: 17.0215%; height: 32px;"><span style="color: #333333;">Resources</span></td><td style="width: 40.1552%; height: 32px;"><span style="color: #333333;">Stored as a file on the client and kept for a set period</span><br><span style="color: #333333;">(uses the user's PC resources)</span></td><td style="width: 42.8232%; height: 32px;"><span style="color: #333333;">Kept on the server until the browser is closed</span><br><span style="color: #333333;">(uses web server resources)</span></td></tr><tr style="height: 33px;"><td style="width: 17.0215%; height: 33px;"><span style="color: #333333;">Expiration</span></td><td style="width: 40.1552%; height: 33px;"><span style="color: #333333;">Kept until the expiration date if one is set<br>(otherwise cleared when the browser closes)</span></td><td style="width: 42.8232%; height: 33px;"><span style="color: #333333;">Varies (depends on configuration)</span></td></tr><tr><td style="width: 17.0215%;"><span style="color: #333333;">Storage format</span></td><td style="width: 40.1552%;"><span style="color: #333333;">text</span></td><td style="width: 42.8232%;"><span style="color: #333333;">object</span></td></tr><tr style="height: 33px;"><td style="width: 17.0215%; height: 33px;">Example uses</td><td style="width: 40.1552%; height: 33px;">Shopping cart,&nbsp;<span>&nbsp;</span><br>remembering ID &amp; password on a login form</td><td style="width: 42.8232%; height: 33px;">Keeping users logged in on a website</td></tr></tbody></table>

Thanks for reading. Corrections are welcome.
