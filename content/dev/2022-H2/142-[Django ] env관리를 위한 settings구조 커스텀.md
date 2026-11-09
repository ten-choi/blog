---
title: "[\bDjango ] env관리를 위한 settings구조 커스텀"
labels: ["Python","django"]
published: true
date: 2022-08-22T16:13:41+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 142
tistoryUrl: "https://yeolceo.tistory.com/142"
tistoryCategory: "Python/django"
tistoryTags: ["django","django","django"]
tistoryPostedAt: "2022-08-22 16:13:41"
language: ko
bloggerPostId: "8216538421051355305"
---
#### ? **환경** 

Mac M1  
Python 3.9  
VsCode

#### ? **개요**

Django의 env값을 Prod, Dev에서 쉽게 사용하고 구분하기 위해 settings 구조를 만들어봅시다!

#### ? **목차**

-   프로젝트를 생성하기
-   결과 확인하기

## **\- 프로젝트 생성하기**

**django-admin startproject config .**   
위의 명령어로 프로젝트를 생성해줍니다. manage.py가 밖으로 빠집니다.  
그리고 **django-admin startapp 앱 이름**  명령어로 app을 만들었을 때 구조가 가독성이 좋습니다.

**pip install python-dotenv** 명령어로 env lib를 설치합니다.  
. env 파일을 manage.py와 동일한 폴더에 생성합니다. 저는 아래와 같이 생성했습니다.  

```typescript
#Local DB
DB_NAME_DEV = "yeol_dev"
DB_NAME_PROD = "yeol_prod"
```

config폴더 내부를 살펴봅시다. settings.py가 존재합니다. settings 폴더를 만들어주세요.  
settings.py는 base.py로 이름을 변경하고 폴더 안에 넣어줍니다.  
해당 폴더 내에 아래와 같은 prod.py, dev.py를 만들어줍니다.

```typescript
파일명 -> dev.py

from .base import *
from dotenv import load_dotenv
load_dotenv(verbose=True) #.env가 누락일경우 경고메시지 출력하는옵션

DB_NAME = os.environ.get("DB_NAME_DEV")
```

```typescript
파일명 -> prod.py

from .base import *
from dotenv import load_dotenv
load_dotenv(verbose=True) #.env가 누락일경우 경고메시지 출력하는옵션

DB_NAME = os.environ.get("DB_NAME_PROD")
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/142/img.webp)

## **\- 결과 확인하기**

세팅이 끝났다면 아래와 같이 settings의 값을 사용합시다.  
settings값을 변수로 가져오면 prod와 dev는 실행할 때의 setting값 변경만으로 컨트롤이 가능합니다.  
저는 API를 하나 만들어 postman을 사용해 테스트를 완료했습니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/142/img_1.webp)

공통의 설정은 base.py에서 컨트롤하면 됩니다. 이렇게 사용하면 local, dev, prod 환경 어디에서든 코드를 깔끔하게 유지할 수 있습니다.

**? 근거 있는 조언은 언제나 환영합니다. 성실한 코딩 하세요.**
