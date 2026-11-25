---
title: "Setting Up and Using Database Replication on MariaDB"
labels: ["Cloud","azure","Archive"]
published: true
date: 2022-01-25T15:31:01+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 122
tistoryUrl: "https://yeolceo.tistory.com/122"
tistoryCategory: "Cloud/azure"
tistoryTags: ["azure","azure","azure","azure","azure"]
tistoryPostedAt: "2022-01-25 15:31:01"
language: en
bloggerPostId: "5650847705795302068"
retitled: true
---
#### Environment

Two Linux servers (Red Hat or CentOS)

#### Overview

This uses MariaDB's replication feature to copy and store data across two or more databases.

We'll split them into a master and a slave.  
Since this gives you real-time backups, you can recover when one side has a problem.

It also lets you spread the DB load.

We'll use both actively, so we'll set each one up as master and slave of the other, and 

#### Contents

-   Check MariaDB on both servers
-   A
-   Creating a load balancer
-   Creating two VMs for LB
-   Setting up httpd on each server
-   LB test

## **Build this by following [https://puham.tistory.com/71](https://puham.tistory.com/71)**

## **\- Installing MariaDB**

Install MariaDB with the commands below. Also check the version to make sure it installed properly.

Install link: pick the right version, grab the yum repository config sdfsdf

sdf

[https://mariadb.org/download/?t=repo-config](https://mariadb.org/download/?t=repo-config)  

```cs
[user]#sudo yum install mariadb -y
[user]#sudo mariadb --version
```

sdf

## **\- MariaDB conf Settings**

Edit the settings for MariaDB.

```cs
[user]# vi /etc/my.cnf
```

When you open it, the source below is the initial default configuration.

```vala
#
# This group is read both by the client and the server
# use it for options that affect everything
#
[client-server]

#
# include *.cnf from the config directory
#
!includedir /etc/my.cnf.d
```

Give the resource group whatever name you like.

**mysql-bin** is the file name of the binary log.

**server-id** just needs to differ between master and slave. Any number works.

**binlog\_format** selects the format (one of STATEMENT, ROW, MIXED).

-   **STATEMENT** \- copies the SQL statements
-   **ROW** \- copies only the changed rows
-   **MIXED** \- copies using a mix of both

**expire\_logs\_days** sets the retention period.

-   binary log = binlog
-   It's the file where everything that happens in MySQL (MariaDB) is recorded.
-   The binary log is disabled by default, so you need to enable it.

Restart MariaDB with the command below.

```cs
[user]# sudo systemctl restart mysqld
```

Then connect to MariaDB with this command. 

```cs
[user]# sudo mysql -u root -p
```

Create a user. 

```routeros
[user]# create user 'repli'@'222.222.222.222' identified by 'password';
```

asdf

## **\- MariaDB Design**

mariadb 

Give the resource group whatever name you like.

Thanks for following along. Happy coding.

## **\- MariaDB Design**

mariadb 

Give the resource group whatever name you like.

Thanks for following along. Happy coding.
