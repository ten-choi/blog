---
title: "[ Aws ] CloudFront 만드는법"
labels: ["Cloud","Cloudfront"]
published: false
date: 2023-01-02T17:38:22+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 156
tistoryUrl: "https://yeolceo.tistory.com/156"
tistoryCategory: "Cloud"
tistoryTags: ["Cloudfront","cloudfront","cloudfront"]
tistoryPostedAt: "2023-01-02 17:38:22"
language: ko
bloggerPostId: "5905370667818162598"
---
#### ? **환경** 

Aws platform

#### ? **개요**

Aws에서 CloudFront를 사용해 FrontEnd 배포를 진행합니다

#### ? **목차**

-   What is the CloudFront
-   How to create CloudFront
-   Err Response Page

## **\- What is the CloudFront** 

Aws의 정적, 동적 웹 콘텐츠를 빨리 배포하도록 지원하는 웹 서비스입니다  
에지 로케이션이라 불리는 데이터 센터가 전 세계 네트워크를 통해 콘텐츠를 제공합니다  
지연시간이 가장 낮은 로케이션으로 라우팅 되는 기능이 있습니다

## **\- How to create CloudFront**

Aws 검색창에서 클라우드 프런트를 검색합니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/156/img.webp)

[S3 만드는 법](https://yeolceo.tistory.com/155)  
Front의 빌드파일이 업로드된 S3의 도메인을 원본 도메인에 설정합니다   
S3 버킷 액세스는 공개로 진행합니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/156/img_1.webp)

뷰어 프로토콜 정책은 https접속을 위해 Redirect Http to Https로 설정합니다  
CloudFront를 향한 접근은 보안을 위해 GET, HEAD만 허용합니다  
캐시 정책은 default로 진행합니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/156/img_2.webp)

[SSL인증 Https도메인 만드는 법](https://yeolceo.tistory.com/154)  
Https 도메인이 따로 없을 경우 위의 방법을 따라가며 리전은 버지니아로 설정하여 진행합니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/156/img_3.webp)

대체 도메인 이름(CNAME)에 항목 추가 버튼을 클릭합니다  
CloudFront에 적용할 https 도메인과 동일하게 기입합니다 e.g) test.test.com  
별도의 대체도메인을 가지고 있다면 해당 도메인을 기입합니다  
그리고 작성된 SSL 인증서를 도메인을 적용합니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/156/img_4.webp)

기본값 루트객체는 index.html로 설정합니다  
S3에 존재하는 FrontEnd 빌드파일의 index.html의 경로를 의미합니다   
배포 생성해 줍니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/156/img_5.webp)

## **\- Err Response page**

만들어진 CloudFront 배포파일을 클릭합니다  
오류페이지에서 오른쪽의 버튼을 클릭합니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/156/스크린샷 2023-01-02 오전 11.48.38.webp)

403, 404 에러는 아래의 이미지처럼 처리합니다  
문제가 생겼을 경우 응답페이지 경로 설정입니다 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/156/img_6.webp)

접속하면 이상 없이 접속이 완료됩니다

**? 근거 있는 조언은 언제나 환영합니다. 성실한 코딩 하세요.**
