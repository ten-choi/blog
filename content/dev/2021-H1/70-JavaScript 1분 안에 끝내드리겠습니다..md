---
title: "JavaScript 1분 안에 끝내드리겠습니다."
labels: ["TS","JS","javascript","JavaScript란","javascript에"]
published: true
date: 2021-01-03T16:07:54+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 70
tistoryUrl: "https://yeolceo.tistory.com/70"
tistoryCategory: "TS, JS/javascript"
tistoryTags: ["JavaScript","JavaScript란","javascript","javascript에"]
tistoryPostedAt: "2021-01-03 16:07:54"
language: ko
bloggerPostId: "7470975223540792394"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/70/img.webp)

#### **\-JavaScript 란**

**html과** **css**를 동적으로 표현하기 위한 **script** 언어입니다. **html, css**만 있으면 웹페이지는 미동도 하지 않습니다!

하지만 네이버 급상승 검색어 같은 걸 보시면 순위가 바뀌는 걸 보실 수 있는데 이런 게 동적인 것이고 J**avaScript**입니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/70/img_1.webp)

로그인 시에 비밀번호가 틀릴 경우 그에 따라 **붉은 글씨로** 표현되거나 **경고창**이 뜨는 경우도 J**avaScript**입니다.

#### **\-History**

처음에는 **LiveScript라는** 명칭을 사용했으나 당시 **Java** 위상이 상당했기에 홍보 목적으로 명칭을

비슷하게 **JavaScript**라고 변경하게 됩니다. 

동적인 웹페이지가 필요하게 되면서 점점 개발자들에게 사용되고

후에는 **ECMA스크립트**라는 표준화된 버전이 존재하게 될 정도 성장합니다!

![위키꺼...](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/70/img_2.webp)

#### **\-사용 방식**

처음 **script** 언어라고 설명드린 것처럼 **html**에서도 **<script>** 태그를 사용합니다.

```html
<!DOCTYPE html>
<html>
	<head>
	</head>
		<body>

  			 <button id="btnAlert" >버튼</button>

			   <script type="text/javascript">
    			    var btnAlert = document.getElementById('btnAlert');
    			    btnAlert.addEventListener('click', function(){
    			        console.log('콘솔아 찍혀라!');
        			})
    			</script>  

		</body>
</html>
```

#### **\-전망**

예전엔 별로로 치부되었으나 요즘에는 **JavaScript**를 기반으로  프런트엔드인 **react.js, vue.js, angular.js** 서버로 쓰이는 **node.js** 등 **JavaScript**기반의 라이브러리나 프레임워크가 대거 등장했습니다. 

제 주관으로 프로그래머는 프로그래밍 언어를 전반적으로 알아야 한다고 생각합니다.

전반적이란 표현에 **JavaScript**는 명실상부 자리 잡을 수 있는 언어라고 일하면서도 실감합니다. (여러 종류의 개발이 있지만 웹 개발 시장은 거대하기에 알아두셔도 손해는 아닐 거라고 생각합니다.)

짧고 간결한 **JavaScript** 정리였습니다. 성실한 코딩 하세요.
