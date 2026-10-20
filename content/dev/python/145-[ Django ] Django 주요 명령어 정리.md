---
title: "[ Django ] Django 주요 명령어 정리"
labels: ["Python","django"]
published: false
date: 2022-08-23T18:23:17+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 145
tistoryUrl: "https://yeolceo.tistory.com/145"
tistoryCategory: "Python/django"
tistoryTags: ["django","django"]
tistoryPostedAt: "2022-08-23 18:23:17"
language: ko
bloggerPostId: "6098411530472698387"
---
#### ? **환경** 

Mac M1  
Python 3.9

#### ? **개요**

Django에서 사용되는 주요 명령어 모음입니다!

#### ? **목차**

-   명령어 종류

## **\- 명령어 종류**

1~8번이 쓸 일이 많습니다.

1.  pip freeze > requirements.txt  
    패키지 목록 text로 저장
2.  pip install -r requirements.txt  
    패키지 목록 인스톨
3.  django-admin startproject 프로젝트이름 .    
    이렇게 해야 현재 폴더에서 프로젝트 생성
4.  python manage.py startapp 앱이름  
    앱 생성
5.  python manage.py runserver 8000  
    해당 포트로 파이썬 실행 
6.  python manage.py runserver --settings=config.settings.dev   
    \--settings = 경로. 경로. 파일. py     해당 경로의 세팅으로 파이썬 실행
7.  python manage.py makemigrations 앱이름  
    앱 이름을 넣으면 해당 앱의 마이그레이션만 생성 -> 의도하지 않은 부분의 생성을 방지  
    models.py에 새로운 Class(table)을 추가하거나 제거할 경우 사용
8.  python manage.py migrate 앱이름  마이그레이션이름  
    앱 이름을 넣으면 해당 앱의 마이그레이션만 반영 -> 의도하지 않은 부분의 반영을 방지  
    마이그레이션 이름을 지정하면 나중에 이전 버전으로 되돌릴 수 있다고 함.  

9.  python manage.py showmigrations 앱이름  
    마이그레이션 적용된 내역 보는 명령어
10.  python manage.py dumpdata  
     백업
11.  python manage.py loaddata  
     로드
12.  python manage.py flush  
     table 내용만 삭제

**? 근거 있는 조언은 언제나 환영합니다. 성실한 코딩 하세요.**
