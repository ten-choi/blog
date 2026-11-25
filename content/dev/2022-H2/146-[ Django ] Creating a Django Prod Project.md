---
title: "[ Django ] Creating a Django Prod Project"
labels: ["Python","django","Archive"]
published: true
date: 2022-09-02T14:32:59+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 146
tistoryUrl: "https://yeolceo.tistory.com/146"
tistoryCategory: "Python/django"
tistoryTags: []
tistoryPostedAt: "2022-09-02 14:32:59"
language: en
bloggerPostId: "5733607603320685031"
---
#### ? **Environment**

Mac M1 pro  
Python 3.9.12  
VsCode  
git Fork

#### ? **Overview**

When working with Django, let's use git too and set up a virtual environment with venv.

## **\- Creating a Django Project**

1.  Create the project on git and clone it into the folder you want
2.  Move to that folder's path
3.  pip install virtualenv -> library for setting up a virtual environment
4.  virtualenv venv --python=python3.8.9  -> the Python version for the virtual environment
5.  source ./venv/bin/activate  -> activate the virtual environment
6.  pip install django -> install Django
7.  pip install djangorestframework -> install DRF for building APIs
8.  pip install djangorestframework-simplejwt -> the DRF JWT library recommended by the official DRF docs
9.  pip install dj-rest-auth -> Django login/auth library
10.  pip install django-allauth -> Django login/auth library
11.  pip install mysqlclient -> DB library
12.  pip freeze > requirements.txt  -> record dependencies
13.  django-admin startproject config .  -> with "config .",  
     it's set up so that manage.py sits outside the directory
14.  django-admin startapp appname    -> set the app name
15.  Django settings -> see the URL later
16.  Set up running the Django debugger in VS Code
17.  python manage.py runserver ->  check that it works   

18.  Create .gitignore -> grab a sample and edit what you need   [https://www.toptal.com/developers/gitignore](https://www.toptal.com/developers/gitignore)   
19.  Set up issue tracking on the git site -> see the URL
20.  pip install django-dotenv  -> add a .env file   need to separate Prod and Dev
21.  Set up VS Code launch.json  
     create debug -> python -> django   
     "program": "${workspaceFolder}/projectName/manage.py",  
     "args": \["runserver", "8000"\],          when there's no env-specific settings  
     "args": \["runserver", "8000", "--settings=projectName.settings.local"\],         when env-specific settings exist
22.  Save the virtual environment's libraries (for recreating the environment elsewhere) ->  pip freeze > requirements.txt     
     \->  install the virtual environment's libraries with pip install -r requirements.txt
23.  Edit or add anything else that comes up later

**? Well-grounded advice is always welcome. Happy coding, and keep at it.**
