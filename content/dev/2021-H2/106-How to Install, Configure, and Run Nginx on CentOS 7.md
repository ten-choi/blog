---
title: "How to Install, Configure, and Run Nginx on CentOS 7"
labels: ["ETC","ETCLanguage","centos","redhat","Archive"]
published: true
date: 2021-10-18T18:03:29+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 106
tistoryUrl: "https://yeolceo.tistory.com/106"
tistoryCategory: "ETC/ETCLanguage"
tistoryTags: ["centos","redhat","centos","centos"]
tistoryPostedAt: "2021-10-18 18:03:29"
language: en
bloggerPostId: "3838830154328639269"
retitled: true
---
\- Environment

OS : Red Hat (CentOS) 

### **\- Installing nginx**

Apparently yum doesn't come with an nginx repository, so you need to add the repository info before installing.

```html
[root@test /]# vi /etc/yum.repos.d/nginx.repo
```

Create the nginx.repo file with vi.

Fill it in like this.

```html
[nginx]
name=nginx repo
baseurl=http://nginx.org/packages/centos/7/$basearch/
gpgcheck=0
enabled=1
```

\[xxxx\] and name are names you choose yourself.

baseurl is the URL of the external repository the packages are fetched from.

GPG is a program that checks whether a package has been tampered with.

When software is distributed, someone could maliciously ship source that differs from the original. GPG provides the publisher's signature or signed files, and this option controls whether that GPG signature is checked. 1 enables it, 0 disables it.

enabled controls whether the repo is added to yum. 1 enables it, 0 disables it.

With the repository set up, install nginx with the command below. -y answers yes to every prompt during installation.  

```html
[root@test /]# yum install -y nginx
```

Check that the installation finished properly with this command.

```html
[root@test /]# nginx -v
```

Once it's installed, move on to the configuration below.

### **\- Configuring nginx** 

Create the conf file nginx will use at the path below.

```html
[root@test /]#  vi /etc/nginx/conf.d/default.conf
```

Configure it like this.

```html
server {
    listen       53001;
    #listen       [::]:8080;

    #server_name  localhost; # where your domain goes

    root /usr/dist/; # dist path of the project to deploy
    index index.html index.htm;

    client_max_body_size 100M;

    location / {
        root /usr/dist;
        index index.html;
        try_files $uri $uri/ /index.html; # path lookup
    }

    location /graphql { # GraphQL goes here; any other API works too
        proxy_pass http://address:54001/graphql;
    }

    error_page 404 /404.html;
        location = /40x.html {
    }

    error_page 500 502 503 504 /50x.html;
        location = /50x.html {
    }
}
```

Set whatever root path you like, and put your dist folder (your frontend build folder) at that root location.

Next, open nginx.conf with the command below. This is the main configuration, and it's what pulls in default.conf.

```html
[root@test /]#  vi /etc/nginx/nginx.conf
```

Scroll down and work from the include line shown below.

```html
include /etc/nginx/conf.d/*.conf; # this line loads every file ending in .conf

Comment out the server block below with #.
(Port 80, which we won't use, can cause problems.)
   # server {
   #     listen       80;
   #     listen       [::]:80;
   #     server_name  _;
   #     root         /usr/share/nginx/html;

   ...
   ...
   ...

   # }
```

Run the command below and nginx is up. It may already be running by default, but run the command once more to be sure.

```html
[root@test /]#   systemctl start nginx
```

If you haven't configured the firewall yet, open the port you'll connect to.

```html
[root@test /]#  sudo firewall-cmd --list-ports
[root@test /]#  sudo firewall-cmd --permanent --zone=public --add-port=53001/tcp
[root@test /]#  sudo firewall-cmd --reload
```

To reach nginx from outside, open http://your-access-ip:port.

Nice work. Happy coding.
