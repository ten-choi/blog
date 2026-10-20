---
title: "[ Resume ] notion 날짜 계산 년, 월, 일로 표현하는 법"
labels: ["Branding","Resume","Formula","notion"]
published: false
date: 2023-07-16T13:58:50+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 181
tistoryUrl: "https://yeolceo.tistory.com/181"
tistoryCategory: "Branding/Resume"
tistoryTags: ["Formula","notion"]
tistoryPostedAt: "2023-07-16 13:58:50"
language: ko
bloggerPostId: "2562354173476537504"
---
notion은 알다시피 많은 개발자들이 이력서로서 활용한다  
그리고 notion에는 database inline이라는 기능이 있다. 그 기능에는 지정한 날짜를 표시하는 기능이 있다  
나는 그곳에 경력 시작일과 종료일을 기입했다. 문제는 여기서 일어났다

notion에는 formula라는 script기반 계산식을 작성할수있는 기능이 있었다  
그래서 기간을 계산식으로 남기고싶어졌다  
formula를 통해서 계산식을 만들었는데 어떤 예시를 봐도 시작일 - 종료일을 통한 day의 산출이었다  
즉, 시작일 2022.01.01, 종료일 2023.01.01 일경우 계산식을 통해 365가 나오는게 모든 블로그의 예시었다  
하지만 나는 YYYY MM DD 가 나오거나 몇 개월 며칠 정도만 체크하고 싶었다

아무리 해도 그 방법이 모호했다 변수도 선언할 수 없고  
날짜를 밀리세컨드로 쪼개봐도 날짜 표현되는 날은 1970년 1월 1일 utc기준으로 나왔다

거기서 발상을 바꿨다 앞의 연도만 빼고 1의 자리만 사용한다면 내가 원하는 방식의 표현이 가능한 것이다  
가져다 쓸 거면 공감이나 댓글 좀 남겨줬으면 좋겠다

```html
prop("to") ? 
	slice(
		concat(
			formatDate(
            	fromTimestamp(
                	dateBetween(
                    	prop("to"), prop("from"), "milliseconds")), "YY년 MM월 DD일")), 1) 
    :slice(
    	concat(
        	formatDate(
            	fromTimestamp(
                	dateBetween(now(), prop("from"), "milliseconds")), "YY년 MM월 DD일")), 1)

한줄요약------------------------------                
prop("to") ? slice(concat(formatDate(fromTimestamp(dateBetween(prop("to"), prop("from"), "milliseconds")), "YY년 MM월 DD일")), 1) : slice(concat(formatDate(fromTimestamp(dateBetween(now(), prop("from"), "milliseconds")), "YY년 MM월 DD일")), 1)
```

그러면 아래와 같이 예쁘게 표현할 수 있다  
시작일과 종료일 기준으로 표현하고 현재 재직중일 경우 now()를 사용한다  

방법이 복잡하긴 하지만 이렇게 만들고 싶었고 시간이 좀 걸렸어도 수식으로 정리한 게 마음에 든다  
나와 비슷한 예시가 없어서 글을 남긴다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/181/img.webp)

그런데 이력서에 넣고싶은데 합계도 넣어야한다면  한로우끼리 계산은 있어도  
각각 로우의 값을 엑셀처럼 들고오는 법은 보이지않았다  
우회하더라도 가능한 방법은 있다 시작일을 본인이 설정해주면된다  
if문을 2번쓰고 1개의 hide table을 만든다 그리고 from이 없는 부분에 시작일을 now - 본인경력일 로 설정하면된다

그리고 11개월하고 그다음월은 12개월이 아니라 0월로 나오고 년이 올라가야하는 계산을 하면 마무리가된다

```html
if(empty(prop("from")) == true,
if(formatDate(fromTimestamp(dateBetween(dateSubtract(now(), 1, "months"), prop("start_job"), "milliseconds")), "M") == "12", 
slice(concat(formatDate(fromTimestamp(dateBetween(now(), prop("start_job"), "milliseconds")), "YY년 0월 DD일")), 1),
slice(concat(formatDate(fromTimestamp(dateBetween(dateSubtract(now(), 1, "months"), prop("start_job"), "milliseconds")), "YY년 MM월 DD일")), 1)), 
if(empty(prop("to")) == false, if(formatDate(fromTimestamp(dateBetween(dateSubtract(prop("to"), 1, "months"), prop("from"), "milliseconds")), "M") == "12", 
slice(concat(formatDate(fromTimestamp(dateBetween(prop("to"), prop("from"), "milliseconds")), "YY년 0월 DD일")), 1), 
slice(concat(formatDate(fromTimestamp(dateBetween(dateSubtract(prop("to"), 1, "months"), prop("from"), "milliseconds")), "YY년 MM월 DD일")), 1)), 
if(formatDate(fromTimestamp(dateBetween(dateSubtract(now(), 1, "months"), prop("from"), "milliseconds")), "M") == "12", 
slice(concat(formatDate(fromTimestamp(dateBetween(now(), prop("from"), "milliseconds")), "YY년 0월 DD일")), 1), 
slice(concat(formatDate(fromTimestamp(dateBetween(dateSubtract(now(), 1, "months"), prop("from"), "milliseconds")), "YY년 MM월 DD일")), 1))))
```

포뮬라는 엔터 단위가 없어서 한줄 코드로 작성해야하기에 아래 한줄코드도 남긴다

```html
if(empty(prop("from")) == true,if(formatDate(fromTimestamp(dateBetween(dateSubtract(now(), 1, "months"), prop("start_job"), "milliseconds")), "M") == "12", slice(concat(formatDate(fromTimestamp(dateBetween(now(), prop("start_job"), "milliseconds")), "YY년 0월 DD일")), 1),slice(concat(formatDate(fromTimestamp(dateBetween(dateSubtract(now(), 1, "months"), prop("start_job"), "milliseconds")), "YY년 MM월 DD일")), 1)), if(empty(prop("to")) == false, if(formatDate(fromTimestamp(dateBetween(dateSubtract(prop("to"), 1, "months"), prop("from"), "milliseconds")), "M") == "12", slice(concat(formatDate(fromTimestamp(dateBetween(prop("to"), prop("from"), "milliseconds")), "YY년 0월 DD일")), 1), slice(concat(formatDate(fromTimestamp(dateBetween(dateSubtract(prop("to"), 1, "months"), prop("from"), "milliseconds")), "YY년 MM월 DD일")), 1)), if(formatDate(fromTimestamp(dateBetween(dateSubtract(now(), 1, "months"), prop("from"), "milliseconds")), "M") == "12", slice(concat(formatDate(fromTimestamp(dateBetween(now(), prop("from"), "milliseconds")), "YY년 0월 DD일")), 1), slice(concat(formatDate(fromTimestamp(dateBetween(dateSubtract(now(), 1, "months"), prop("from"), "milliseconds")), "YY년 MM월 DD일")), 1))))
```
