---
title: "[ Slack ] Sending Messages to Slack from a Node Server and Receiving Responses"
labels: ["ThirdParty","Slack","node","Archive"]
published: true
date: 2022-06-10T15:14:51+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 134
tistoryUrl: "https://yeolceo.tistory.com/134"
tistoryCategory: "ThirdParty/Slack"
tistoryTags: ["slack","slack","Slack","node"]
tistoryPostedAt: "2022-06-10 15:14:51"
language: en
bloggerPostId: "6424180471742320734"
---
#### Environment

NodeJS 16v  
koa

#### Overview

We'll send a message from a Node server to Slack with buttons like Yes/No, register a POST API URL for those buttons, and receive the clicks on the server as a hook.

The environment is Node and Slack, so I'll assume both are already installed. I'm using koa as the library, but it's almost the same as express, so feel free to follow along with either.

#### Contents

-   What is Slack
-   Node server setup 1
-   Slack configuration
-   Node server setup 2
-   Passing data to the hook server through Slack message buttons

## **\- What Is Slack**

It's described as a cloud-based team collaboration tool. Think of it as a beefed-up desktop KakaoTalk. It's a messenger app for work where you send messages, coordinate schedules, share files, and so on. Many companies use a dedicated work messenger for various reasons, including keeping work separate from KakaoTalk, which people use for personal stuff.

## **\- Node Server Setup 1**

Import axios to send API requests for Slack messages. Match the object format to what Slack expects, as described in this [link](https://api.slack.com/legacy/outmoded-messaging).

We'll fill in the url and auth variables later as we go.

```bash
import axios from 'axios';

export default async (ctx: any) => {

  const data: object = {
    channel: 'test',  

    attachments: [
      {
        title: `test title `,
        text: `Sending a message ~`,
      },
    ],
  };

  const config: object = {
    method: 'post',
    url:  '',
    headers: {
      'Content-Type': 'application/json',
      Authorization: '' 
    },
    data,
  };

  const result = await axios(config)
    .then((data: any) => {
      console.log(data);
    })
    .catch((err: any) => {
      console.error(err);
    });

  return (ctx.body = result);
};
```

## **\- Slack Configuration**

Once Slack is installed and running, first create a new workspace for testing.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/134/img.webp)

Then click the add channel button, set the channel name you want, and create the channel.

This is the channel name we'll send API requests to, so give it an English name.

Next, go to the [**Slack**](https://api.slack.com/) API site. Log in and click Your apps (underlined).

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/134/img_1.webp)

On the page below, create a new app. Think of it as creating an app so we can use Slack!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/134/img_2.webp)

I named mine yeoltest.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/134/img_3.webp)

Follow the categories on the left and you'll find OAuth, the category for authentication, permissions, and issuing tokens. Get a token there.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/134/img_4.webp)

When setting the token's permissions, add chat:write.public under Scopes as shown below. Don't worry about the other ones that were added.

The token can post in Slack channels once it has the chat permission!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/134/img_5.webp)

The required configuration is done. Let's update the Node source and send an API request.

## **\- Node Server Setup 2**

Fill in whatever was missing from Server Setup 1 using the block below.

```bash
export default async (ctx: any) => {
  const ctxBody: object = ctx.request.body;

  const data: object = {
    channel: 'test',

    attachments: [
      {
        title: `test1`,
        text: `Let's gooooooooooooooooooooooooooooooooooooooo:  `,

      },
    ],
  };

  const config: object = {
    method: 'post',
    url: 'https://slack.com/api/chat.postMessage',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer xoxb-364your-token`, 
    },
    data,
  };

  const result = await axios(config)
    .then((data: any) => {
      console.log(data);
    })
    .catch((err: any) => {
      console.error(err);
    });

  return (ctx.body = result);
};
```

Now send a request, and the message shows up in the Slack channel.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/134/img_6.webp)

Congrats! You've already implemented basic messaging.

## **\- Passing Data to the Hook Server Through Slack Message Buttons**

Up to this point, the feature works cleanly. But if this is a platform actually in service, for example, you might need a format the CS team can review and act on.

On the site where you issued the token, click Interactivity & Shortcuts in the left categories. When Slack sends a POST API request from a button click, you register the URL here in advance and call it via a callback ID. Other messaging systems work similarly.

Create one by referring to the image below. I made a simple one like this.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/134/img_7.webp)

As shown above, I set the URL that will receive the hook. The source isn't much different from before; just add the changes below (e.g. callback\_id).

```bash
const data: object = {
    channel: 'test', 

    attachments: [
      {
        title: `test1`,
        text: `Let's gooooooooooooooooooooooooooooooooooooooo:  `,
        color: '#2980B9',
        callback_id: 'yeol_action',
        attachment_type: 'default',
        actions: [
          {
            name: 'buttonName',
            text: 'text~~~',
            type: 'button',
            value: `your value`,
          },
        ],
      },
    ],
  };
```

You can also set up two buttons for Yes/No, or receive whatever values you need.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/134/img_8.webp)

If it ran fine like above, congrats! If you want to use Slack messaging without an auth token, use Incoming Webhooks from the categories. You can send messages to Slack with just a URL.

Happy coding, and keep at it!
