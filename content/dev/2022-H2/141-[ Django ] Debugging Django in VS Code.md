---
title: "[ Django ] Debugging Django in VS Code"
labels: ["Python","django","vscode","Archive"]
published: true
date: 2022-08-19T12:43:56+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 141
tistoryUrl: "https://yeolceo.tistory.com/141"
tistoryCategory: "Python/django"
tistoryTags: ["django","vscode","django"]
tistoryPostedAt: "2022-08-19 12:43:56"
language: en
bloggerPostId: "3221132261069754628"
---
#### ? **Environment**

Mac M1  
Python 3.9.12  
VsCode

#### ? **Overview**

If you use VS Code for Django, use debug mode!

#### ? **Contents**

-   VsCode Debug setting in Django

## **\- VsCode Debug setting in Django**

In VS Code, press F5 or click the bug icon in the left sidebar to see how to run debug mode.

1.  Go to debug settings -> select Python -> select Django. This creates a .vscode folder and a launch.json file.
2.  Referring to the code block below, set the value of program to match the directory of manage.py.
3.  In args, enter the values manage.py needs when it runs: runserver, port, and settings.  
    settings is optional and only needed if you've split up settings.py.

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
      "program": "${workspaceFolder}/folderName/manage.py",
      "args": ["runserver", "8000"],
      #optional
      #"args": ["runserver", "8000", "--settings=projectName.settings.local"],
      "django": true,
      "justMyCode": true
    }
  ]
}
```

**? Well-grounded advice is always welcome. Happy coding, and keep at it.**
