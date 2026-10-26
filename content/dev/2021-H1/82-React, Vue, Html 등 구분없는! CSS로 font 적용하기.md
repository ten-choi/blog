---
title: "React, Vue, Html 등 구분없는! CSS로 font 적용하기"
labels: ["TS","JS","react","폰트","html","vue","css","angular"]
published: false
date: 2021-02-03T13:10:24+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 82
tistoryUrl: "https://yeolceo.tistory.com/82"
tistoryCategory: "TS, JS/react"
tistoryTags: ["폰트","react","html","vue","css","angular"]
tistoryPostedAt: "2021-02-03 13:10:24"
language: ko
bloggerPostId: "93022873544095991"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img.webp)

**Css**에서 **font**를 적용할 수 있게끔 지원하는 기능이 있습니다. 그래서 **html, vue, anguler** 이런 구분이 없이 적용할 수 있습니다.

필자는 **React**를 주로 쓰기 때문에 **React**에서 **font**를 적용하는 예시를 보여드립니다.

(다른 프런트 언어를 사용하셔도 이해하기 쉬운 글입니다)

### **\-폰트 적용하는 방법**

1\. npm 명령어를 사용하여 **React** 프로젝트를 만들어줍니다. 

```html
npm create-react-app font-test  // 이름은 편한대로 설정해주세요.
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img_1.webp)

그리고 **App.js** 파일로 이동하여 화면에 보이는 부분을 **깔끔하게 정리**해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img_2.webp)

보기 편하기 위해 **폰트 사이즈**를 50px로 설정했습니다.

![첫화면은 이렇게 생겼습니다.](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img_3.webp)

2\. **눈누**라는 무료 폰트 사이트를 이용했습니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img_4.webp)

원하는 폰트 하나를 정해서 클릭해주세요. 저는 **산돌 삼립 호빵체**를 사용했습니다. (호빵이 꽂히네요)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img_5.webp)

여기서 선택지가 나뉩니다. **font**를 **다운로드**해서 적용하느냐 **웹주소**로 **폰트**를 불러와서 적용을 하느냐입니다.

2개다 해볼 텐데 먼저 웹폰트를 사용해보겠습니다.

### **\-웹폰트를 사용하는 법**

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img_6.webp)

**React** 프로젝트에서 **App.css** 에 폰트를 적용하기 위한 코드를 입력해줍니다. 

**\*font-face 란 css3부터 적용가능한 글꼴 명세 기능입니다.**

```html
@font-face {
    font-family: 'this_is_font_name';  //원하는 이름을 입력해주세요
    src: url('https://cdn.jsdelivr.net/gh/projectnoonnu/noonfonts-20-12@1.0/SDSamliphopangche_Outline.woff') format('woff');
    ㄴ  // 폰트의 경로를 설정해주세요
     font-weight: normal; //폰트의 두께를 설정해주세요
     font-style: normal;  //폰트의 스타일을 설정해주세요
}
.App {
  text-align: center;
  font-size: 50px;  //폰트 사이즈 키웠습니다.
  font-family: this_is_font_name;  // font-face에서 설정한 폰트 이름입니다.
}
```

**Css**에 변경이 끝났다면 **React** 화면을 보시면 예쁘게 잘 적용이 됐습니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img_7.webp)

### **\-저장된 폰트 사용하는 법**

1\. 웹폰트가 아닌 **다운로드**를 클릭해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img_8.webp)

2\. 아래와 같은 화면이 나오면 **다운로드**를 클릭해주면 아래로 이동됩니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img_9.webp)

**이동된 화면**에서 **TTF** 다운로드를 클릭해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img_10.webp)

3\. **React** 프로젝트에서 src 폴더에 **fonts**라는 폴더를 만들어주세요.

   다운로드한 **font** 압축파일을 해당 폴더에서 압축 풀기를 진행해주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img_11.webp)

4\. 위와 같은 설정이지만 **src**(경로) 부분이 다릅니다. **App.css** 에서 fonts 경로를 통해 다운로드한 **ttf** 폰트 파일명을 적어줍니다.

```html
@font-face {
    font-family: 'write_font_name';
    src: url(./fonts/SDSamliphopangcheTTFOutline.ttf) format('woff');
    font-weight: normal;
    font-style: normal;
}
.App {
  text-align: center;
  font-size: 50px;
  font-family: write_font_name;
}
```

font의 종류는 2가지였습니다. **SDSamliphopangcheTTFOutline**를 사용한 이유는 **Outline** 폰트가 변경했다는 부분이 부각되서입니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/82/img_12.webp)

변경됐다는 점을 위해 글자도 바꿔보았습니다.

font 적용 잘 되셨길 바랍니다. 성실한 코딩 하세요~
