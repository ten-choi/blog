---
title: "[ Django ] django \bdebug on VsCode"
labels: ["Python","django","vscode"]
published: false
date: 2022-08-19T12:43:56+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 141
tistoryUrl: "https://yeolceo.tistory.com/141"
tistoryCategory: "Python/django"
tistoryTags: ["django","vscode","django"]
tistoryPostedAt: "2022-08-19 12:43:56"
language: ko
bloggerPostId: "3221132261069754628"
---
#### ? **환경** 

Mac M1  
Python 3.9.12  
VsCode

#### ? **개요**

Django를 사용할 때 VsCode를 사용하는 경우 디버그 모드를 사용합시다!

#### ? **목차**

-   VsCode Debug settting in Django

## **\- VsCode Debug settting in Django**

VsCode에서 F5를 누르거나 왼쪽 카테고리에 벌레 모양 그림을 클릭하면 디버그 모드를 실행하는 법을 알 수 있습니다.

1.  디버그 설정 -> python 선택 -> django 선택을 진행할 경우. vscode 폴더 및 launch.json 파일이 생성
2.  아래 코드 블록을 참조하며 program의 value 설정할 때 manage.py의 디렉터리를 맞춰서 세팅
3.  args에는 manage.py를 실행할 때 필요한 runserver, port, settings 값을 입력  
    settings의 경우 settings.py를 구분했을 때만 사용하는 optional입니다.

```bash
{
  // Use IntelliSense to learn about possible attributes.
  // Hover to view descriptions of existing attributes.
  // For more information, visit:  
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Python: Django",
      "type": "python",
      "request": "launch",
      "program": "${workspaceFolder}/폴더명/manage.py",
      "args": ["runserver", "8000"],
      #optional
      #"args": ["runserver", "8000", "--settings=프로젝트이름.settings.local"],
      "django": true,
      "justMyCode": true
    }
  ]
}
```

**? 근거 있는 조언은 언제나 환영합니다. 성실한 코딩 하세요.**
