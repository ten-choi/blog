---
title: "How to Install Node.js on CentOS 7"
labels: ["OS","Linux","centos","centos7","Archive"]
published: true
date: 2020-10-13T13:29:28+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 53
tistoryUrl: "https://yeolceo.tistory.com/53"
tistoryCategory: "OS/Linux"
tistoryTags: ["centos","linux","centos7","centos"]
tistoryPostedAt: "2020-10-13 13:29:28"
language: en
bloggerPostId: "6460481199096168096"
---
## **\-CentOS 7 Commands**

### sudo

Runs a command with root privileges.

### curl 

A command-line tool for transferring data. It's handy for uploads and downloads,

so it's mostly used to fetch the data you need.

### bash

A type of shell. You use a shell to give the computer commands as text and run them.

### yum

Short for Yellowdog Updater, Modified. It's the package manager used on Red Hat-based distros. 

## **\-Commands to Install Node, in Order**

### **curl -sL [https://rpm.nodesource.com/setup\_12.x](https://rpm.nodesource.com/setup_12.x) | sudo bash -**

### **curl -sL https://rpm.nodesource.com/setup\_16.x | sudo bash -**

The URLs above are NodeSource setup scripts for Node.js 12 or 16. They handle binary distribution and repository setup.

Put simply, they fetch the data for a specific Node version onto your machine so you can use that version.

### **sudo yum clean all && sudo yum makecache fast**

`yum clean all` wipes the whole cache.

`makecache` then rebuilds the cache with the latest data, which apparently speeds things up.

### **sudo yum install -y gcc-c++ make**

This installs the GNU C++ compiler (gcc being the GNU Compiler Collection) and make.

### **sudo yum install -y nodejs**

Now install Node.js itself. 

### **node -v**

Check the version to make sure it installed correctly.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/53/img.webp)

**Error case 1**

**If you get "no package nodejs available", it means the curl step didn't add Node to your yum repositories.**

### yum install epel-release -y

EPEL stands for Extra Packages for Enterprise Linux. Install these extra Linux packages, then run `yum install nodejs -y` again. Keep in mind that this way there's no info about the version you want, so you'll get Node's default version.

Hope it worked for you. Happy coding!
