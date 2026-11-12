---
title: "[ Intellij ] 한글깨짐 문제 해결"
labels: ["IDE","Editor","Intellij"]
published: true
date: 2024-03-18T10:08:53+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 213
tistoryUrl: "https://yeolceo.tistory.com/213"
tistoryCategory: "IDE, Editor/Intellij"
tistoryTags: ["IntelliJ","KR"]
tistoryPostedAt: "2024-03-18 10:08:53"
language: ko
bloggerPostId: "8595644152951090768"
---
글삭이나 변경을 예방하기위해 가져왔으며 아래 링크의 분의 작성글을 카피함  
문제가 될시 글삭 혹은 내용 변경  
[https://www.lesstif.com/java/intellij-file-console-encoding-121012310.html](https://www.lesstif.com/java/intellij-file-console-encoding-121012310.html)

# IntelliJ 한글 깨짐 문제 해결(file 과 console encoding 설정)

인텔리제이에서 WAS 구동시나 app 실행시 한글이 깨진다면 보통 인코딩 설정이 잘못 되어서입니다.

대부분의 경우 UTF-8 encoding 을 사용할테니 다음 방법으로 encoding 을 정확히 설정해 주면 됩니다.

## file/console encoding 설정

1. **Settings**  → **Editor**  → **File Encodings**  에 들어갑니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/213/img.webp)

**2\. Global** 과 **Project**  Encoding 을 설정(1)하고 **properties**  파일의 인코딩(2)도 설정해 줍니다.

프로퍼티 파일에 다음과 같이 한글을 인코딩했다면  "Tranparent native-to-ascii conversion" 을 설정해 주면 자동으로 변환되서 표시됩니다.

```clean
## \uC804\uC5ED
```

Plain text

Copy

CODE

## VM 옵션 설정

1. **Help** → "**Edit Custom VM options**" 를 선택합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/213/img_1.webp)

2\. vmoption 에 file 과 console 인코딩 옵션을 추가해 줍니다.

```ini
-Dfile.encoding=UTF-8
-Dconsole.encoding=UTF-8
```

Plain text

Copy

CODE

3\. 설정이 끝났으면 **File**  → "**Invalidate Caches**" 를 선택합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/213/img_2.webp)

4. **"Invalidate and Restart"** 를 선택하면 캐시를 삭제하고 IntelliJ 가 재시작됩니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/213/img_3.webp)
