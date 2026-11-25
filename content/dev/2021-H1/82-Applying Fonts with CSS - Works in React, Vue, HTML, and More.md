---
title: "Applying Fonts with CSS - Works in React, Vue, HTML, and More!"
labels: ["TS","JS","react","Font","html","vue","css","angular","Archive"]
published: true
date: 2021-02-03T13:10:24+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 82
tistoryUrl: "https://yeolceo.tistory.com/82"
tistoryCategory: "TS, JS/react"
tistoryTags: ["폰트","react","html","vue","css","angular"]
tistoryPostedAt: "2021-02-03 13:10:24"
language: en
bloggerPostId: "93022873544095991"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img.webp)

**CSS** has built-in support for applying a **font**. That means it works the same whether you're using **HTML, Vue, or Angular**.

I mostly use **React**, so I'll show an example of applying a **font** in **React**.

(It's easy to follow even if you use a different front-end framework)

### **\-How to Apply a Font**

1\. Create a **React** project with npx.

```html
npx create-react-app font-test  // name it whatever you like
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img_1.webp)

Then go to **App.js** and **clean up** what's shown on screen.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img_2.webp)

I set the **font size** to 50px so it's easier to see.

![This is what the first screen looks like.](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img_3.webp)

2\. I used a free font site called **Noonnu**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img_4.webp)

Pick a font you like and click it. I used **Sandoll Samlip Hoppang**. (The hoppang one just grabbed me)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img_5.webp)

Here you have two options: **download** the **font** and use it locally, or load the **font** from a **web URL**.

I'll try both, starting with the web font.

### **\-Using a Web Font**

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img_6.webp)

In your **React** project, add the code that applies the font to **App.css**.

**\*@font-face is a font declaration feature available since CSS3.**

```html
@font-face {
    font-family: 'this_is_font_name';  //enter whatever name you want
    src: url('https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts-20-12@1.0/SDSamliphopangche_Outline.woff') format('woff');
       // set the path to the font
     font-weight: normal; //set the font weight
     font-style: normal;  //set the font style
}
.App {
  text-align: center;
  font-size: 50px;  //bumped up the font size
  font-family: this_is_font_name;  // the font name you set in @font-face
}
```

Once you've updated the **CSS**, check the **React** screen and you'll see it applied nicely.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img_7.webp)

### **\-Using a Downloaded Font**

1\. Click **Download** instead of the web font option.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img_8.webp)

2\. When you see the screen below, clicking **Download** scrolls you down the page.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img_9.webp)

On **that section**, click the **TTF** download.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img_10.webp)

3\. In your **React** project, create a folder called **fonts** inside the src folder.

   Extract the downloaded **font** zip file into that folder.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img_11.webp)

4\. The setup is the same as above, but the **src** (path) part is different. In **App.css**, point to the downloaded **ttf** font file through the fonts path.

```html
@font-face {
    font-family: 'write_font_name';
    src: url(./fonts/SDSamliphopangcheTTFOutline.ttf) format('truetype');
    font-weight: normal;
    font-style: normal;
}
.App {
  text-align: center;
  font-size: 50px;
  font-family: write_font_name;
}
```

The font came in two variants. I used **SDSamliphopangcheTTFOutline** because the **Outline** style makes it obvious the font changed.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img_12.webp)

I also changed the text to make the change stand out.

I hope the font worked for you. Happy, diligent coding~
