---
title: "Setting Up and Using Load Balancing with Nginx"
labels: ["ETC","Nginx","Archive"]
published: true
date: 2022-01-17T13:48:27+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 119
tistoryUrl: "https://yeolceo.tistory.com/119"
tistoryCategory: "ETC/Nginx"
tistoryTags: ["nginx","nginx","nginx","nginx"]
tistoryPostedAt: "2022-01-17 13:48:27"
language: en
bloggerPostId: "6814027169277304478"
retitled: true
---
#### Environment 

Linux (Red Hat or CentOS)  
Nginx  

#### Overview

We'll run an LB test with two servers using Nginx.  
\-> I'll call load balancing "LB" for short.

#### Contents

-   Installing Nginx
-   Configuring upstream
-   Designing a real-world Nginx LB setup
-   Security issues caused by SELinux

### **\- Installing Nginx**

Update the package manager and install nginx. Installing with dnf works too.

```html
sudo yum update -y  
sudo yum install nginx -y
```

Once it's installed, check the version with **nginx -v** to make sure it installed properly. Then move to the path shown in the image below. pwd is the command that prints the current directory.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/119/img.webp)

The **nginx.conf** in that directory is the file that configures how the **nginx** server behaves. You can view or edit the nginx settings with **vi nginx.conf**. Go ahead and run **vi nginx.conf**.

Check the **default port** in **nginx.conf**. Try connecting from your PC using the IP of the server where nginx is installed and the default port set in nginx. Port 80 was already in use on my machine, so I changed it to 3001.

```html
http {

   server {
        listen       3001 default_server; # changed to 3001 since 80 is in use
        root         /usr/share/nginx/html;

    }
}
```

If you can't connect from outside, turn off the firewall. Stop the firewall service, and use reload to check that it stopped properly.

```dockerfile
systemctl stop firewalld
firewall-cmd --reload
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/119/img_1.webp)

Try accessing it by IP from a browser outside the server.

If you see the default nginx page, installation and testing are done.

### **\- Configuring upstream**

upstream is where you register the servers nginx will connect to for LB. If you don't specify an LB method, it defaults to round robin. As in the code block below, I named my upstream lbtest.

```html
http {
    upstream lbtest {
        server your-server-ip:81;
        server your-server-ip:82;
   }

   server {
        listen       3001 default_server; # changed to 3001 since 80 is in use
        root         /usr/share/nginx/html;

        location /{
           proxy_pass http://lbtest;
        }

        #error_page 404 /404.html;
        #    location = /40x.html {
        #}

        # error_page 500 502 503 504 /50x.html;
        #    location = /50x.html {
        #}
    }
```

Here's what it actually looks like.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/119/제목 없음.webp)

Register two or more servers in upstream lbtest. Any reachable server works: httpd, Node, Java, and so on.

**proxy\_pass** is used when the nginx IP is accessed from outside. It reroutes the incoming request to the path given in proxy\_pass. If you've set up an upstream, it load-balances across the servers listed in that upstream.

To test load balancing, set proxy\_pass in location to lbtest as above.

**Watch out  
****1\. location /  
**2\. location /test  
**If you register the same upstream for nginx paths like these, and the example upstream IP is 111.111.111.111:81,** **#1 hits 111.111.111.111:81 as configured, but #2 hits 111.111.111.111:81/test, which may not be what you intended.  

**

**\[See the example code block below\]**

```html
http {
    upstream lbtest {
        server 111.111.111.111:81; 
        server your-server-ip:82;   
   }

   server {
        listen       3001 default_server; # changed to 3001 since 80 is in use
        root         /usr/share/nginx/html;
        location /{
           proxy_pass http://lbtest;
        }

        #######################################
        #location /test{
        #  proxy_pass http://lbtest; 

           # doing this gives you the IP set in lbtest + the extra path -> you get the following
           #server 111.111.111.111:81/test  

        #}
        ########################################
    }
```

Once nginx is configured, apply the settings with restart. reload works too, but restart is better at catching errors in the conf file, so I prefer it.

```css
systemctl restart nginx.service
```

Access nginx from outside and check that each refresh alternates between the registered servers.

If you take down one of the two URLs registered in upstream, only the remaining one will be served.

This post is about load balancing, but I also tested server clustering, a similar concept.

My tests confirmed that both Nginx upstream and Azure LB, with no extra configuration, support putting a single proxy IP in front of all the servers and routing calls around any server that has a problem.

### **\- Designing a Real-World Nginx LB Setup**

If you're not using the LB features of AWS or Azure, you can build a dedicated LB server with nginx's upstream feature.

When you access the nginx server, you reach the front servers registered in upstream frontLoadBalancer.

The front end then calls the API at the nginx server's /graphql. The nginx server forwards that API call to the servers registered in backLoadBalancer, so both front and back can be load-balanced.

```html
location /{
           proxy_pass http://frontLoadBalancer;
        }

        location /graphql {
           proxy_pass http://backLoadBalancer;
        }
```

### **\- Security Issues Caused by SELinux**

If you can't reach nginx and check the nginx error log, you may see a message like this.

\-> nginx permission denied while connecting to upstream

Check the HTTP network connection settings with the command below.

```html
#getsebool -a | grep http
```

If httpd\_can\_network\_connect is off, you need to turn it on.

It's the access security policy for HTTP.

```html
#setsebool httpd_can_network_connect on -P
```

That's it for Nginx LB. Happy coding.
