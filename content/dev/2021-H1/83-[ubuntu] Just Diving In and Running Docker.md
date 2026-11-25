---
title: "[ubuntu] Just Diving In and Running Docker"
labels: ["ETC","Docker","Archive"]
published: true
date: 2021-02-05T17:05:04+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 83
tistoryUrl: "https://yeolceo.tistory.com/83"
tistoryCategory: "ETC/Docker"
tistoryTags: ["docker","docker","docker","Docker","docker","docker"]
tistoryPostedAt: "2021-02-05 17:05:04"
language: en
bloggerPostId: "889168884370948342"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/83/img.webp)

#### **\-What Is Docker**

An open-source, **container-based** virtualization platform that makes it easy to build, test, and deploy applications.

-   **Container**: holds a running process. Since the container itself is the running process, it doesn't care about the environment,  
    which makes it easy to modify, deploy, and scale.  

-   **Image**: stores the executables and configuration needed to run a container.

### **\-**Docker** Hands-On**

Log in to Ubuntu as **root**. (You need the privileges because Docker has to touch Linux resources)

Install **docker** with this command.

```html
apt install docker.io
```

-   **How Docker works**

It downloads images from **Docker Hub** into your Docker **registry** and works through the process shown in the image below.

**\-If you've used git**, a lot of it will feel familiar, which makes it easier to understand

![https://www.notion.so/b67ed727aea4467cbc3226bb0c8e8336  Source: Jaejulbof's Docker course for absolute beginners](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/83/img_1.webp)

\* The **run command** does pull, create, and start all at once.

To run a **container**, you can go step by step with **pull, create, start**,

or do everything up to running it with just the **run** command.

Let's use **nginx** from **Docker Hub** to go through **download, run, stop, and delete**.

#### \-Download and Run

First, the step-by-step way with **pull, create, start**. Download **nginx** with the pull command.

```html
docker pull nginx
```

Once the download finishes, create an **nginx** **container**.

\--name sets the name to nx, and -p sets the port; the 8080 on the left is the port we'll type into the browser.

```html
docker create --name nx -p 8080:80 nginx
```

Now run the container, with its name and port set, using the **start** command.

```html
docker start nx
```

Open localhost:8080 in your web browser. Did it come up like below?

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/83/img_2.webp)

Next is the way using the **run** command. Delete both the existing **nginx** container and image,

then try this command!

```html
docker run -d --name nx -p 8080:80 nginx
```

**run** does it all in one go. Open **localhost:8080** and you'll see **nginx** running.

#### \-Stop and Delete

Docker's **ps** command (process status) shows any running containers. With the **\-a** option (all), stopped containers are printed to the terminal too.

```html
docker ps
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/83/img_3.webp)

We gave the container a name, so let's use it. Stop and delete the container

with the stop and rm commands.

```html
docker stop nx
```

```html
docker rm nx
```

Check that it's gone with docker ps -a.

Then check the image you downloaded with pull.

```html
docker images
```

Once you see the image, put its ID into the command below and run it.

```html
docker rmi <IMAGE ID>
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/83/img_4.webp)

We just dove in and went through one full loop, from installing **docker.io** with apt to **downloading, running, stopping, and deleting** a container.

Give it a try yourself and fill in the details as you go.

Nice work, and happy, diligent coding.
