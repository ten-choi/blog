---
title: "[ Django ] Key Django Commands"
labels: ["Python","django","Archive"]
published: true
date: 2022-08-23T18:23:17+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 145
tistoryUrl: "https://yeolceo.tistory.com/145"
tistoryCategory: "Python/django"
tistoryTags: ["django","django"]
tistoryPostedAt: "2022-08-23 18:23:17"
language: en
bloggerPostId: "6098411530472698387"
---
#### ? **Environment**

Mac M1  
Python 3.9

#### ? **Overview**

A collection of the main commands used in Django!

#### ? **Contents**

-   Commands

## **\- Commands**

You'll use 1 through 8 a lot.

1.  pip freeze > requirements.txt  
    Save the package list as text
2.  pip install -r requirements.txt  
    Install the package list
3.  django-admin startproject projectname .    
    Adding the dot creates the project in the current folder
4.  python manage.py startapp appname  
    Create an app
5.  python manage.py runserver 8000  
    Run Python on that port
6.  python manage.py runserver --settings=config.settings.dev   
    \--settings=path.path.file     Run Python with the settings at that path
7.  python manage.py makemigrations appname  
    Passing an app name creates migrations only for that app -> prevents generating migrations you didn't intend  
    Use this when you add or remove a Class (table) in models.py
8.  python manage.py migrate appname  migrationname  
    Passing an app name applies migrations only for that app -> prevents applying changes you didn't intend  
    Apparently, specifying a migration name lets you roll back to a previous version later.  

9.  python manage.py showmigrations appname  
    Shows which migrations have been applied
10.  python manage.py dumpdata  
     Backup
11.  python manage.py loaddata  
     Load
12.  python manage.py flush  
     Delete only the table data

**? Well-grounded advice is always welcome. Happy coding, and keep at it.**
