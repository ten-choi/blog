---
title: "[ Django ] django Prod 프로젝트 만들기"
labels: ["Python","django"]
published: false
date: 2022-09-02T14:32:59+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 146
tistoryUrl: "https://yeolceo.tistory.com/146"
tistoryCategory: "Python/django"
tistoryTags: []
tistoryPostedAt: "2022-09-02 14:32:59"
language: ko
bloggerPostId: "5733607603320685031"
---
#### ? **환경** 

Mac M1 pro  
Python 3.9.12  
VsCode  
git Fork

#### ? **개요**

Django를 사용할때 git도쓰고 venv를 사용하여 가상환경 구축합시다.

## **\- Django Project 생성 과정**

1.  git에서 프로젝트를 생성하고 원하는 폴더에 clone을 다운로드
2.  해당 폴더의 경로로 이동
3.  pip install virtualenv -> 가상환경 설정을 위한 lib
4.  virtualenv venv --python=python3.8.9  -> 가상환경 설치시 파이썬 버전
5.  source ./venv/bin/activate  -> 가상환경 실행
6.  pip install django -> django 설치
7.  pip install djangorestframework -> api 사용을 위한 drf 설치
8.  pip install djangorestframework-simplejwt -> drf공문에서 추천하는 drf jwt
9.  pip install dj-rest-auth -> django 로그인 auth lib
10.  pip install django-allauth -> django 로그인 auth lib
11.  pip install mysqlclient -> db lib
12.  pip freeze > requirements.txt  -> 의존성 기록
13.  django-admin startproject config .  -> config . 을 할경우  
     manage.py가 디렉토리 밖으로 나오는 구조로 셋팅 됨
14.  django-admin startapp 앱이름    -> 앱이름 설정하기
15.  djang setttings -> 이후 url 참조
16.  VSCode dajngo debug 실행 설정 
17.  python manage.py runserver ->  작동 확인   

18.  .gitignore 생성 -> 샘플받고 수정 필요한거 수정   [https://www.toptal.com/developers/gitignore](https://www.toptal.com/developers/gitignore)   
19.  git 사이트에서 이슈관리 생성 -> url 참조
20.  pip install django-dotenv  -> .env 파일 추가   Prod, Dev 구분필요
21.  vscode launch.json 셋팅  
     create debug -> python -> django   
     "program": "${workspaceFolder}/프로젝트이름/manage.py",  
     "args": \["runserver", "8000"\],          env설정용 셋팅 없을때  
     "args": \["runserver", "8000", "--settings=프로젝트이름.settings.local"\],         env설정용 셋팅 존재할때
22.  가상환경lib 저장 (다른곳에서 환경 새로 만들때) ->  pip freeze > requirements.txt     
     \->  가상환경lib 인스톨 pip install -r requirements.txt
23.  이후 추가 되는거 있으면 수정이나 추가

**? 근거 있는 조언은 언제나 환영합니다. 성실한 코딩 하세요.**
