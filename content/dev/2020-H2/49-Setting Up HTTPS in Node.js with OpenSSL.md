---
title: "Setting Up HTTPS in Node.js with OpenSSL"
labels: ["ETC","SSL","OpenSSL","node.js","Archive"]
published: true
date: 2020-09-24T18:15:50+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 49
tistoryUrl: "https://yeolceo.tistory.com/49"
tistoryCategory: "ETC/SSL"
tistoryTags: ["OpenSSL","openssl","node.js"]
tistoryPostedAt: "2020-09-24 18:15:50"
language: en
bloggerPostId: "6792058715713319792"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/49/img.webp)

## What Is OpenSSL?

OpenSSL is an open-source implementation of TLS and SSL, the protocols used for data communication over a network.

SSL stands for Secure Sockets Layer.

Put simply, it's a technology that encrypts the data sent between websites and servers.

TLS stands for Transport Layer Security.

It's the newer, stronger successor to SSL.

In short, it's the technology that encrypts data in transit on the web.

## Downloading the Tool to Create a Certificate

First, download the tool for creating SSL certificates from the link below.

[sourceforge.net/projects/openssl/](https://sourceforge.net/projects/openssl/)

Once you download and unzip it, you'll see something like this.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/49/img_1.webp)

Follow the folder path and you'll find a file called openssl.exe.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/49/img_2.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/49/img_3.webp)

Once you run it, you should see a command-prompt-like window like the one above.

## Creating the Certificate

req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 3650

Enter the command above and you'll get a certificate valid for 10 years. -> Fill in the name fields and password however you like.

(I'll update this with an explanation of the command once I've studied it more.)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/49/img_4.webp)

You'll end up with two files, key.pem and cert.pem, as shown above. Now let's take these files

over to the Node.js server. (If you're not sure how to run a Node.js server, see the link below.)

[yeolceo.tistory.com/29](https://yeolceo.tistory.com/29)

If you've already been running an HTTP server with Express or Koa:

```html
option = {
      key: fs.readFileSync('./open_ssl/openssl-0.9.8k_X64/bin/key.pem'),
      cert: fs.readFileSync('./open_ssl/openssl-0.9.8k_X64/bin/cert.pem'),
      //Adjust the paths to match your setup.
      passphrase:'put your password here',
      agent:false
  };

// app must already be an Express or Koa app that can call app.listen.

  https.createServer(option, app).listen(5050, () => {
      console.log(`[HTTPS] Soda Server is started on port ${5050}`)
  });
```

Then just run it from the command prompt as usual.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/49/img_5.webp)

Node.js should now be running over HTTPS.

Since this isn't a certificate from a trusted authority, the browser will of course show it as "Not secure" or display a warning.

Corrections are always appreciated. Thanks!
