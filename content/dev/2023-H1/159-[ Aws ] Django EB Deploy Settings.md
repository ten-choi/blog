---
title: "[ Aws ] Django EB Deploy Settings"
labels: ["Cloud","eb","django","Archive"]
published: true
date: 2023-01-18T10:20:49+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 159
tistoryUrl: "https://yeolceo.tistory.com/159"
tistoryCategory: "Cloud"
tistoryTags: ["eb","django"]
tistoryPostedAt: "2023-01-18 10:20:49"
language: en
bloggerPostId: "4110405257198754174"
---
#### ? **Environment** 

Python 3.8  
VsCode  
ELB

#### ? **Overview**

Setting things up to run Django on EB. 

#### ? **Contents**

-   EB deploy settings
-   Examples

## **\- EB Deploy Settings**

**See the examples at the bottom.**

1.  Install the EB CLI
2.  In your project, run `eb init` and follow the prompts  
    For "Do you wish to continue with CodeCommit?", answer N  
    (It's asking whether you want to use AWS CodeCommit as your repository.)
3.  A config.yml file is created inside .elasticbeanstalk
4.  .ebignore: lists files that don't need to be uploaded to EB -> e.g.) Example 4
5.  .ebextensions: package or data settings used by EB -> e.g.) Example 5  
    ├── 01\_package.config  
    ├── 02\_gunicorn.config  
    └── 03\_env.config
6.  .platform: commands to run at each EB deploy stage  
    [aws\_postdeploy\_link](https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/platforms-linux-extend.html) (how to use it)  
    ├── hooks  
     │   └── postdeploy  
     │       ├── 01\_env.sh  
     │       └── 02\_gunicorn.sh  
    └── nginx  
        └── conf.d  
            └── elasticbeanstalk  
                └── nginx\_custom.conf
7.  eb deploy

## **\- Examples**

```python
# Example 4
# file_name: .ebignore

.env
.git
.gitignore 
/venv
```

```python
# Example 5
# file_name: 01_package.config

commands:
  01-command:
    command: sudo yum install -y mysql-devel
  02-command:
    command: sudo yum install -y jq
```

```python
# Example 5
# file_name: 02_gunicorn.config

files:
  "/etc/systemd/system/gunicorn.service":
    mode: "000755"
    owner: root
    group: root
    content: |
      [Unit]
      Description=gunicorn daemon
      After=network.target

      [Service]
      WorkingDirectory=/var/app/current/<project_name> #project path
      Environment="DJANGO_SETTINGS_MODULE=<project_name>.settings.local" #project settings path
      ExecStart=/var/app/venv/staging-LQM1lest/bin/gunicorn \      #venv gunicorn path
      --workers 3 --bind 0.0.0.0:8000 <project_name>.wsgi:application --timeout 120

      [Install]
      WantedBy=multi-user.target

container_commands:
  1_command:
    command: "systemctl enable gunicorn"
  2_command:
    command: "systemctl start gunicorn"
```

```python
# Example 5
# file_name: 03_env.config

option_settings:
  aws:elasticbeanstalk:application:environment:
    DJANGO_SETTINGS_MODULE: <project_name>.settings.local
    LOCAL_ENV : False
    DB_NAME_DEV : test_db_name
```

```python
# Example 6
# file_name: 01_env.sh
# Reads the env and copies it into the directory where it's used; join the 3 lines below into one line

#!/bin/sh
/opt/elasticbeanstalk/bin/get-config environment
| jq -r 'to_entries | .[] | "\(.key) = \"\(.value)\""' > 
/var/app/current/<project_name>/.env
```

```bash
# Example 6
# file_name: 02_gunicorn.sh
# Restart after the deploy finishes

#!/bin/sh
sudo systemctl restart gunicorn
```

```python
# Example 6
# file_name: nginx_custom.conf
# Use when you need custom nginx settings
```

**? Well-grounded advice is always welcome. Code with care.**
