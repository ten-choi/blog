---
title: "JavaScript in Under a Minute"
labels: ["TS","JS","javascript","Archive"]
published: true
date: 2021-01-03T16:07:54+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 70
tistoryUrl: "https://yeolceo.tistory.com/70"
tistoryCategory: "TS, JS/javascript"
tistoryTags: ["JavaScript","JavaScript란","javascript","javascript에"]
tistoryPostedAt: "2021-01-03 16:07:54"
language: en
bloggerPostId: "7470975223540792394"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/70/img.webp)

#### **\- What Is JavaScript?**

It's a **scripting** language for making **HTML** and **CSS** dynamic. With just **HTML and CSS**, a web page doesn't move an inch!

But take something like Naver's trending search terms: you can watch the rankings change. That's dynamic, and that's **JavaScript**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/70/img_1.webp)

When you enter the wrong password at login and get **red text** or a **warning popup**, that's **JavaScript** too.

#### **\- History**

It was originally called **LiveScript**, but since **Java** was so prominent at the time, it was renamed to the similar-sounding

**JavaScript** for marketing purposes.

As dynamic web pages became necessary, more and more developers started using it,

and it grew to the point where a standardized version called **ECMAScript** came to exist!

![From the wiki...](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/70/img_2.webp)

#### **\- How It's Used**

As I said at the start, it's a **scripting** language, so in **HTML** you use the **<script>** tag.

```html
<!DOCTYPE html>
<html>
	<head>
	</head>
		<body>

  			 <button id="btnAlert" >Button</button>

			   <script type="text/javascript">
    			    var btnAlert = document.getElementById('btnAlert');
    			    btnAlert.addEventListener('click', function(){
    			        console.log('Print to the console!');
        			})
    			</script>  

		</body>
</html>
```

#### **\- Outlook**

It used to be dismissed as so-so, but these days a wave of **JavaScript**-based libraries and frameworks has appeared: **react.js, vue.js, and angular.js** on the frontend, **node.js** on the server, and more.

In my opinion, a programmer should have a broad understanding of programming languages.

And in that broad picture, I feel at work that **JavaScript** has undeniably earned its place. (There are many kinds of development, but the web development market is huge, so knowing it won't hurt.)

That was a short and sweet **JavaScript** summary. Happy coding!
