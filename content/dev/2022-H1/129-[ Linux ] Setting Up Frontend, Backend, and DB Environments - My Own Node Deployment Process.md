---
title: "[ Linux ] Setting Up Frontend, Backend, and DB Environments - My Own Node Deployment Process"
labels: ["OS","Linux","Environment Setup","Load Balancing","MSA","Backend","Failover","Archive"]
published: true
date: 2022-04-04T14:59:15+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 129
tistoryUrl: "https://yeolceo.tistory.com/129"
tistoryCategory: "OS/Linux"
tistoryTags: ["환경설정","부하분산","MSA","백엔드","장애대응"]
tistoryPostedAt: "2022-04-04 14:59:15"
language: en
bloggerPostId: "5276696490903992039"
---
#### Environment

CentOS Stream 8

#### Overview

This covers the basic environment setup on CentOS, up to the point where you can start developing. It's mainly for my own reference. I've put in all the keywords, so search for whatever's missing.

#### Contents

-   Environment setup
-   Notes explaining the steps above

## **\- Environment Setup**

We start from a CentOS machine already created on VMware, Azure, AWS, or similar.

Open up the firewall as needed on your own. I'll assume three servers.

\- Backend server

First, install Node.

```html
https://rpm.nodesource.com # git site that explains the Node installation below

curl -sL https://rpm.nodesource.com/setup_16.x | sudo -E bash # install v16, the current LTS
yum clean all # clear the cache
yum install -y nodejs # install node
```

Check node and npm, then install pm2.

```html
node -v # check it installed correctly; if it tells you to update, go ahead

npm i -g --save pm2 # install pm2 first for zero-downtime operation and cluster management
```

\- Frontend server

Install nginx to serve the frontend build files.

```html
https://www.nginx.com/resources/wiki/start/topics/tutorials/install/  # just google "nginx install"
# create a file named nginx.repo with vi at the path below, containing the text below
# you can check the baseurl link and adjust it for your system; I'm on CentOS 8, so I used 8
# [root@localhost yum.repos.d]# pwd  -> /etc/yum.repos.d

[nginx]
name=nginx repo
baseurl=https://nginx.org/packages/centos/8/$basearch/ 
gpgcheck=0
enabled=1
```

Once the repo is registered, install and start it.

```html
yum install nginx -y # install
systemctl start nginx # start
systemctl enable nginx # start the nginx service automatically on boot
```

\- Database

For MariaDB, create a repo the same way and install it.

Decide whether to go with **[replication (reference)](https://server-talk.tistory.com/240)** or **[Galera clustering (reference)](https://m.blog.naver.com/PostView.naver?isHttpsRedirect=true&blogId=taemojin&logNo=221577342665)**.

**[HAProxy reference](https://dev-youngjun.tistory.com/97)** Nginx can do load balancing too, but let's use something tailored to databases.

This is for failover and load balancing.

## **\- Notes Explaining the Steps Above**

\# For nginx, set worker\_processes auto; to use all CPUs, then scale out and load-balance later  
\# For pm2, run multiple cluster instances to use all CPUs  
\# For both, load balancing can be done with AWS or Azure features, or with nginx. pm2 can also be load-balanced with nginx.  
\# Even if you load-balance by URL, if one server goes down, nginx or the cloud service can handle it at the LB level.

\# A good **[link on zero-downtime deployment](https://velog.io/@kakasoo/Node.js%EC%9D%98-Clustering-Module-%EB%A1%9C%EB%93%9C-%EB%B0%B8%EB%9F%B0%EC%8B%B1)**

I used pm2 and nginx here, but the basics are: run the maximum number of processes, and think about load balancing, failover, and zero-downtime deployment.  
A service with real users -> once you have users, load balancing and failure detection are a must.  
Why I don't mention AWS blue-green or Docker for zero downtime: AWS costs money, and Docker—use it if your company does.

If you start as a monolith like above and later move to MSA, split by business domain and develop the same way.  
On the DB side, design carefully with ERDCloud and add proper schema indexing.

Using Ngrok ->

When you don't want to pay for something like AWS, run three servers on VMware, make sure the API communication works, and then hook just the frontend up to a free Ngrok domain to allow external access. In other words, everything talks internally and only the frontend gets a free public domain.

Well-grounded advice is always welcome. Happy coding, and keep at it.
