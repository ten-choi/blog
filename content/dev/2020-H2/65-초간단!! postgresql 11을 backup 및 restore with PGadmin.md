---
title: "초간단!! postgresql 11을 backup 및 restore with PGadmin"
labels: ["DB","rdb","postgresql","postgres"]
published: true
date: 2020-12-28T16:50:38+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 65
tistoryUrl: "https://yeolceo.tistory.com/65"
tistoryCategory: "DB/rdb"
tistoryTags: ["postgresql","postgres","postgresql","postgres","postgres"]
tistoryPostedAt: "2020-12-28 16:50:38"
language: ko
bloggerPostId: "6187098831635333253"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img-png.webp)

#### PG admin을 사용하기 때문에 배우기 쉬운 백업 및 리스토어 방법입니다!! 

## **1\. postgresql db 만들기**

#### 먼저 pg admin을 실행해줍시다.   (미리 설치는 해 두셔야되용...!)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_1-png.webp)

#### 아래의 이미지를 따라 우클릭 -> Create -> Database...  를 순서대로 클릭해줍니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_2-png.webp)

#### 데이터베이스의 명칭은 forbackup으로 했습니다.  백업용이란 의미를 부여하고 싶었습니다.

#### 자 이제 forbackup db 가 손쉽게 완성되었습니다!    바로 테이블을 만들어줍시다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img.webp)

#### 저희는 쿼리를 사용하여 테이블을 만들어주겠습니다. 

#### 아래의 이미지를 따라 테이블-> 우클릭을 통해 쿼리툴을 클릭해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_3-png.webp)

#### 아래의 코드를 사용해서 바로 테이블을 만들어줍니다. 

```html
CREATE TABLE tb_test (
  "seq" SERIAL not null PRIMARY KEY,
  "age" integer not null,
  "name" character varying(32) not null
);
```

#### 잘 만들었다면 아래의 이미지를 따라 만든 테이블을 확인해봅시다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_4-png.webp)

#### 정보를 입력해줍니다. (이 정도는 수동으로 갑시다...  2개만 써도 돼요...)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_5.webp)

#### 그럼 아주 손쉽게 db 테이블에 행과 열이 완성이 됐습니다.

## **2\. postgresql db back up 하기**

#### 자 이제 백업 시작합니다.

#### forbackup db를 우클릭해준 후 나온 list에서 Backup 을 선택합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_6.webp)

#### back up 전의 설정 화면이 바로 나올 것입니다.

#### 분홍색 네모 박스를 그려놓은 부분을 클릭해줍니다. 저장할 경로와 백업 파일명을 정하는 곳입니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_7.webp)

#### 저는 바탕화면에 bk\_File 이란 폴더를 만들었습니다. 

#### 그리고 dump1이라는 백업 파일 명을 사용하겠습니다. 아래의 포맷은 sql로 설정해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_1.webp)

#### backup 할 포맷 타입은 Tar로 설정해줍니다. (tar은 linux의 압축 방식 중 하나입니다.)

#### 완료되었다면 Backup 버튼을 눌러 백업을 종료해주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_2.webp)

#### 축하드립니다. 하주 손쉽게 백업에 성공하셨습니다. 생성하신 폴더 내부를 확인해보면

#### 여러분이 만든 파일명. sql로 된 파일이 존재할 것입니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_3.webp)

## **3\. postgresql db restore 하기**

#### 쉬어 갈 틈이 없습니다. 곧바로 저희는 forrestore라는 명의 database를 만들어줍시다.

#### 방법은 이전과 동일하며 명칭은 restore용 db를 연상시키려 했습니다. (명칭은 중요합니다.)

#### 만든 database를 우클릭을 통해 아래와 같은 창을 띄워줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_8.webp)

#### 첫 번째 라인의 default 가 저희가 설정한 포맷과 동일하니 넘어가 줍니다.  

#### 백업 파일을 찾아주기 위해 바로 두 번째 라인으로 가줍니다. 오른쪽 붉은 선위의 점 3개 박스를 선택!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_9.webp)

#### 저희가 저장해 두었던 dump1 파일을 찾아주고 select 해줍니다!!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_4.webp)

#### 더 건드릴 필요 없이 Restore 버튼으로 빠르게 마무리해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_10.webp)

#### 여러분도 아래와 같이 성공했다는 표시가 나오셨나요?

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_11.webp)

#### 확인해 보시면 forrestore db에서 tb\_test를 확인하실 수 있습니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_12.webp)

#### 이렇게 마무리해주시면 아주 쉽고 간단한 백업 및 리스토어 되겠습니다.

#### 잘 만드셨다면 축하드립니다. 성실한 코딩 하세요.
