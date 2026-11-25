---
title: "Resetting a Lost MariaDB/MySQL Root Password on Windows"
labels: ["DB","rdb","mysql","MariaDB","Archive"]
published: true
date: 2021-11-19T16:45:35+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 109
tistoryUrl: "https://yeolceo.tistory.com/109"
tistoryCategory: "DB/rdb"
tistoryTags: ["mysql","MariaDB","MariaDB","mysql"]
tistoryPostedAt: "2021-11-19 16:45:35"
language: en
bloggerPostId: "1642588024917517269"
---
#### \-Environment

OS: Windows 10  
DB: MariaDB 10.3.13

### \-Password Reset and Update

#### **1\. Stop the MySQL service**

Open "Run" in Windows (shortcut: Windows+R).  
Type **services.msc** and run it. In the Services window, stop the MySQL service.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/109/img.webp)

#### **2\. Start MySQL without the grant tables**

Find the bin folder of your MySQL or MariaDB installation, then cd into it in cmd.  
(In my case, C:\\Program Files\\MariaDB 10.3\\bin)  

```html
cd C:\Program Files\MariaDB 10.3\bin
```

Run either the first or the second command. It means "start up and skip the privilege checks."

```html
mysqld -uroot --skip-grant-tables 
OR
mysqld --skip-grant
```

The cmd window will appear to hang and print a log line along the lines of "mysqld starting process".

#### **3\. Connect to MySQL and change the password**

Open a new cmd window and run the command below from the same folder.

```html
mysql -uroot mysql
```

\-Then set the password you want with an update statement.

```html
update user set password = PASSWORD('plz input your password') WHERE user = 'root';
```

\-For MySQL 5.7 and later (FLUSH PRIVILEGES: clears the old cache and applies the new settings)

```html
update user set authentication_string= PASSWORD('plz input your password') WHERE user = 'root';
 FLUSH PRIVILEGES;
```

You'll see a completion log. If the Changed count in it is non-zero, the change worked.  
Restart the MySQL service from the Services window. If you get an error at this point, reboot your computer.

#### **4\. Test it**

Even if you normally use an editor like Workbench, connect directly from cmd with the command below and enter the password to test it.

```html
mysql -u root -p
```

**Last resort**

[https://goodteacher.tistory.com/291](https://goodteacher.tistory.com/291)

See this post.

Happy coding.
