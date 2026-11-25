---
title: "Using the NCP SMS API with Node.js"
labels: ["TS","JS","nodejs","sms","naver","sens","Archive"]
published: true
date: 2020-06-11T12:46:26+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 21
tistoryUrl: "https://yeolceo.tistory.com/21"
tistoryCategory: "TS, JS/nodejs"
tistoryTags: ["sms","naver","naver","sens"]
tistoryPostedAt: "2020-06-11 12:46:26"
language: en
bloggerPostId: "6036625967639913154"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/21/img.webp)

**This post shows how to use Naver's SMS API, which gives you 50 free messages. Please bear with me, as the code is split into chunks.**

I used Atom as my editor.

First, let's set up a Node.js project.

Run `npm init`, edit the generated JSON file, then run `npm install`, and the basic setup is done.

I'll create an `app.js` file and run that.

Put it wherever is convenient for you.

With just this, you can already run the Node app.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/21/img_1.webp)

```html
const express = require('express');

const app = express(); 
const crypto = require('crypto');  // Used for hashing. The SMS API requirements say to use this too.
const request = require('request'); 
const app = express(); // 
const PORT = 3000 ; 

app.listen(PORT, ()=>{console.log('http://localhost:3000/m gonna be your localhost')}  );
```

The crypto part can be hard to follow, so let's set it aside for now.

Between the `require`s and `listen`, we'll write a GET route.

That's because we're going to call it from the browser's address bar. For the path, I used `m`, short for "message."

```html
app.get('/m', (req, res)=>{    // we use localhost3000/m 
	 const phone = '01088889999'; // Recipient's phone number
	 const accessKey = 'access key';		access key 
     const secretKey = 'secret key';        secret key 
     const serviceID = 'service ID'     where the service ID goes
     const myphone = '01012314564'; //    Your registered phone number
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/21/img_2.webp)

The service ID is here. Click the key icon on the right and grab the ID value, not the secret.

Next, let's set up the values needed to call the API.

[https://apidocs.ncloud.com/ko/common/ncpapi/#API-%ED%98%B8%EC%B6%9C%ED%95%98%EA%B8%B0](https://apidocs.ncloud.com/ko/common/ncpapi/#API-%ED%98%B8%EC%B6%9C%ED%95%98%EA%B8%B0)

Everyone says they work from this doc, but I looked at what other people had done, got it working first with this, and understood it afterward.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/21/img_3.webp)

On that page, it tells you how to create an API key.

After logging in, go to My Page -> Manage API Keys to create one.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/21/img_4.webp)

This is where you get the access key and secret key.

You can only use the SMS API after authenticating with both the project ID and your account's API keys.

[https://docs.ncloud.com/ko/sens/sens-1-3.html](https://docs.ncloud.com/ko/sens/sens-1-3.html)

You need to register an SMS project and your own phone number before you can use it. Up to this point, Naver's docs are pretty friendly.

Fill in the registered number in the code above, and the basic authentication setup is done.

Now for the signature. From here on, I had to read Naver's docs carefully.

```html
const space = " ";          	 // one space
     const newLine = "\n";           // new line
     const method = "POST";          // method

     const url = `https://sens.apigw.ntruss.com/sms/v2/services/${serviceID}/messages`;

	 // url (include query string) Added when building the signature.
     const urlsub = `/sms/v2/services/${serviceID}/messages`;

     const timestamp = Date.now().toString();   // The docs say it fails if the time difference is too large.
     												// So we include the timestamp too.

     let hmac=crypto.createHmac('sha256',secretKey);
	 let mes = [];    // Create an array. I didn't do this for the key setup, but it's easier to read this way.
     // Short for "message". Name it meaningfully, like we did with the route path.
     mes.push(method);
     mes.push(space);
     mes.push(urlsub);
     mes.push(newLine);
     mes.push(timestamp);
     mes.push(newLine);
     mes.push(accessKey);
     const signature = hmac.update(mes.join('')).digest('base64');
     // update feeds the mes value into the crypto (hashing) function we set up as hmac.
     // join combines the array's values; if you pass a parameter, it's inserted
     // between each element.
```

[https://apidocs.ncloud.com/ko/common/ncpapi/migration\_server/](https://apidocs.ncloud.com/ko/common/ncpapi/migration_server/)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/21/img_5.webp)

As for how the signature is built, even the spaces and line breaks are strictly defined.

With Naver's SMS API, it helps to think of it in two parts: building the signature, and calling the API with `request`.

**Congratulations. You're almost there.**

Now that the signature is done, let's get ready to make the call.

[https://apidocs.ncloud.com/ko/ai-application-service/sens/sms\_v2/](https://apidocs.ncloud.com/ko/ai-application-service/sens/sms_v2/)

This is the API section for sending SMS.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/21/img_6.webp)

It's all laid out in the image. Let's follow it step by step.

That said, since I learned by studying the finished version, I recommend looking at the complete code below first.

```html
// We've finished setting up the path, so let's send the request.

    request({
         method: method,    // We set this to POST above
         json: true,   	// json must be true so the header values are JSON
         uri: url,  // Put the path parameter here.
         headers: {
             'Content-Type': 'application/json; charset=utf-8',
             'x-ncp-iam-access-key' : accessKey,         // here
             'x-ncp-apigw-timestamp': timestamp,
             'x-ncp-apigw-signature-v2': signature.toString()
         },
         body: {
             "type":"SMS",
             "contentType":"COMM",
             "countryCode":"82",
             "from": myPhoneNumber,
             "content":`code service ${verificationCodeIfYouWantOne}`,        // here
             "messages":[
                 {
                     "to":`${phone}`,          // here
                 }
             ]
         }
     },function (err, res, html) {
         if(err) console.log(err);
         console.log(html);
     });
 });
```

Each field documents how it should be used. Check them carefully as you go.

The code is now complete. In cmd, run Node in that folder.

Then open [http://localhost:3000/m](http://localhost:3000/) in your browser.

If your phone is registered and the code is right, the SMS you sent should land on your phone. Thanks for reading!
