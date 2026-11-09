---
title: "[ Aws ] django eb deploy setting"
labels: ["Cloud","eb","django"]
published: true
date: 2023-01-18T10:20:49+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 159
tistoryUrl: "https://yeolceo.tistory.com/159"
tistoryCategory: "Cloud"
tistoryTags: ["eb","django"]
tistoryPostedAt: "2023-01-18 10:20:49"
language: ko
bloggerPostId: "4110405257198754174"
---
#### ? **환경** 

Python 3.8  
VsCode  
ELB

#### ? **개요**

Django를 eb에서 실행하기 위한 세팅을 진행합니다. 

#### ? **목차**

-   eb deploy setting
-   보기 참조

## **\- eb deploy setting**

**보기는 하단 참조**

1.  eb cli 설치
2.  프로젝트에서 명령어-> eb init 하고 설명에 맞게 진행  
    Do you wish to continue with CodeCommit? N을 눌러줍니다  
    저장소를 Aws의 코드커밋으로 하겠냐는 질문
3.  . elasticbeanstalk내부에 config.yml 파일 생성됨
4.  . ebignore eb에 올라가지 않아도 될 파일 생성 -> e.g) 5번 보기
5.  . ebextensions  eb에 사용될 pakaage 혹은 data 설정 -> e.g) 6번 보기  
    ├── 01\_package.config  
    ├── 02\_gunicorn.config  
    └── 03\_env.config
6.  . platform eb에서 사용될 deploy 단계에 맞게 실행할 명령어 설정  
    [aws\_postdeploy\_link](https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/platforms-linux-extend.html) 사용법 링크  
    ├── hooks  
     │   └── postdeploy  
     │       ├── 01\_env.sh  
     │       └── 02\_gunicorn.sh  
    └── nginx  
        └── conf.d  
            └── elasticbeanstalk  
                └── nginx\_custom.conf
7.  eb deploy

## **\- 보기 참조**

```python
# 4번 보기
# file_name: .ebignore

.env
.git
.gitignore 
/venv
```

```python
# 5번 보기
# file_name: 01_package.config

commands:
  01-command:
    command: sudo yum install -y mysql-devel
  02-command:
    command: sudo yum install -y jq
```

```python
# 5번 보기
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
# 5번 보기
# file_name: 03_env.config

option_settings:
  aws:elasticbeanstalk:application:environment:
    DJANGO_SETTINGS_MODULE: <project_name>.settings.local
    LOCAL_ENV : False
    DB_NAME_DEV : test_db_name
```

```python
# 6번 보기
# file_name: 01_env.sh
# env를 읽어 사용할 디렉토리에 카피하는 작업, 아래 3줄 한줄로 만들어서 사용

#!/bin/sh
/opt/elasticbeanstalk/bin/get-config environment
| jq -r 'to_entries | .[] | "\(.key) = \"\(.value)\""' > 
/var/app/current/<project_name>/.env
```

```bash
# 6번 보기
# file_name: 01_gunicorn.sh
# deploy가 끝나고 restart

#!/bin/sh
sudo systemctl restart gunicorn
```

```python
# 6번 보기
# file_name: nginx_custom.conf
# nginx custom setting 필요할때 사용
```

**? 근거 있는 조언은 언제나 환영합니다. 성실한 코딩 하세요.**
