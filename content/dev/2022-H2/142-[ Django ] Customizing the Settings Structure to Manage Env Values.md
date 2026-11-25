---
title: "[ Django ] Customizing the Settings Structure to Manage Env Values"
labels: ["Python","django","Archive"]
published: true
date: 2022-08-22T16:13:41+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 142
tistoryUrl: "https://yeolceo.tistory.com/142"
tistoryCategory: "Python/django"
tistoryTags: ["django","django","django"]
tistoryPostedAt: "2022-08-22 16:13:41"
language: en
bloggerPostId: "8216538421051355305"
---
#### ? **Environment**

Mac M1  
Python 3.9  
VsCode

#### ? **Overview**

Let's build a settings structure so Django env values are easy to use and keep separate between Prod and Dev!

#### ? **Contents**

-   Creating the project
-   Checking the result

## **\- Creating the Project**

**django-admin startproject config .**   
Create the project with the command above. manage.py ends up at the top level.  
Then when you create an app with **django-admin startapp appname**, the structure is nice and readable.

Install the env library with **pip install python-dotenv**.  
Create a .env file in the same folder as manage.py. I created mine like this:  

```typescript
#Local DB
DB_NAME_DEV = "yeol_dev"
DB_NAME_PROD = "yeol_prod"
```

Let's look inside the config folder. There's a settings.py. Create a settings folder.  
Rename settings.py to base.py and move it into the folder.  
In that folder, create prod.py and dev.py as shown below.

```typescript
File name -> dev.py

from .base import *
from dotenv import load_dotenv
load_dotenv(verbose=True) # option that prints a warning if .env is missing

DB_NAME = os.environ.get("DB_NAME_DEV")
```

```typescript
File name -> prod.py

from .base import *
from dotenv import load_dotenv
load_dotenv(verbose=True) # option that prints a warning if .env is missing

DB_NAME = os.environ.get("DB_NAME_PROD")
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/142/img.webp)

## **\- Checking the Result**

Once the setup is done, use the settings values like below.  
If you pull settings values into variables, you can switch between prod and dev just by changing the settings value when you run it.  
I made a single API and finished testing it with Postman.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/142/img_1.webp)

Shared settings can be controlled in base.py. Set it up this way and you can keep your code clean across local, dev, and prod environments.

**? Well-grounded advice is always welcome. Happy coding, and keep at it.**
