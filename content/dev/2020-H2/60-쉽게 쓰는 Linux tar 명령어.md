---
title: "쉽게 쓰는 Linux tar 명령어"
labels: ["OS","Linux","tar"]
published: true
date: 2020-11-24T11:22:25+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 60
tistoryUrl: "https://yeolceo.tistory.com/60"
tistoryCategory: "OS/Linux"
tistoryTags: ["tar","Linux","linux","linux","tar"]
tistoryPostedAt: "2020-11-24 11:22:25"
language: ko
bloggerPostId: "6218452766757088929"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/60/img.webp)

tar \[-option\]  \[filename\]

 tar -cvf aaa.tar.gz abc 압축하기

 tar -xvf aaa.tar.gz   압축 풀기

 tar -zcvf aaa.tar.gz abc

 tar -zxvf aaa.tar.gz  

\-f 대상 file을 지정합니다.

\-c 기존의 파일을 tar 압축형태로 만들때 사용합니다.

\-v 명령어 처리과정을 터미널에 출력합니다.

x- 기존의 tar 파일을 합축해제할때 사용합니다.

tar 아카이브에서 파일 추출. (파일

 tar \[OPTION...\] \[FILE\]... 

        -f     : 대상 tar 아카이브 지정. (기본 옵션)  
        -c     : tar 아카이브 생성. 기존 아카이브 덮어 쓰기. (파일 묶을 때 사용)  
        -x     : tar 아카이브에서 파일 추출. (파일 풀 때 사용)  
        -v     : 처리되는 과정(파일 정보)을 자세하게 나열.  
        -z     : gzip 압축 적용 옵션.  
        -j     : bzip2 압축 적용 옵션.  
        -t     : tar 아카이브에 포함된 내용 확인.  
        -C     : 대상 디렉토리 경로 지정.  
        -A     : 지정된 파일을 tar 아카이브에 추가.  
        -d     : tar 아카이브와 파일 시스템 간 차이점 검색.  
        -r     : tar 아카이브의 마지막에 파일들 추가.  
        -u     : tar 아카이브의 마지막에 파일들 추가.  
        -k     : tar 아카이브 추출 시, 기존 파일 유지.  
        -U     : tar 아카이브 추출 전, 기존 파일 삭제.  
        -w     : 모든 진행 과정에 대해 확인 요청. (interactive)  
        -e     : 첫 번째 에러 발생 시 중지

tar 사용 예명령어 옵션

<table style="border-collapse: collapse; width: 100%;" border="1"><tbody><tr><td><a href="https://recipes4dev.tistory.com/146#31-%ED%98%84%EC%9E%AC-%EB%94%94%EB%A0%89%ED%86%A0%EB%A6%AC%EC%9D%98-%EB%AA%A8%EB%93%A0-%ED%8C%8C%EC%9D%BC%EA%B3%BC-%EB%94%94%EB%A0%89%ED%86%A0%EB%A6%AC%EB%A5%BC-tar%EB%A1%9C-%EB%AC%B6%EA%B8%B0">현재 디렉토리의 모든 파일과 디렉토리를 tar로 묶기</a></td><td>tar cvf T.tar *</td></tr><tr><td><a href="https://recipes4dev.tistory.com/146#32-%EB%8C%80%EC%83%81-%EB%94%94%EB%A0%89%ED%86%A0%EB%A6%AC%EB%A5%BC-%ED%8F%AC%ED%95%A8%ED%95%9C-%EB%AA%A8%EB%93%A0-%ED%8C%8C%EC%9D%BC%EA%B3%BC-%EB%94%94%EB%A0%89%ED%86%A0%EB%A6%AC%EB%A5%BC-tar%EB%A1%9C-%EB%AC%B6%EA%B8%B0">대상 디렉토리를 포함한 모든 파일과 디렉토리를 tar로 묶기</a></td><td>tar cvf T.tar [PATH]</td></tr><tr><td><a href="https://recipes4dev.tistory.com/146#33-%ED%8C%8C%EC%9D%BC%EC%9D%84-%EC%A7%80%EC%A0%95%ED%95%98%EC%97%AC-tar-%EC%95%84%EC%B9%B4%EC%9D%B4%EB%B8%8C%EB%A1%9C-%EB%AC%B6%EA%B8%B0">파일을 지정하여 tar 아카이브로 묶기</a></td><td>tar cvf T.tar [FILE_1] [FILE_2]</td></tr><tr><td><a href="https://recipes4dev.tistory.com/146#34-tar-%EC%95%84%EC%B9%B4%EC%9D%B4%EB%B8%8C%EB%A5%BC-%ED%98%84%EC%9E%AC-%EB%94%94%EB%A0%89%ED%86%A0%EB%A6%AC%EC%97%90-%ED%92%80%EA%B8%B0">tar 아카이브를 현재 디렉토리에 풀기</a></td><td>tar xvf T.tar</td></tr><tr><td><a href="https://recipes4dev.tistory.com/146#35-tar-%EC%95%84%EC%B9%B4%EC%9D%B4%EB%B8%8C%EB%A5%BC-%EC%A7%80%EC%A0%95%EB%90%9C-%EB%94%94%EB%A0%89%ED%86%A0%EB%A6%AC%EC%97%90-%ED%92%80%EA%B8%B0">tar 아카이브를 지정된 디렉토리에 풀기</a></td><td>tar xvf T.tar -C [PATH]</td></tr><tr><td><a href="https://recipes4dev.tistory.com/146#36-tar-%EC%95%84%EC%B9%B4%EC%9D%B4%EB%B8%8C%EC%9D%98-%EB%82%B4%EC%9A%A9-%ED%99%95%EC%9D%B8%ED%95%98%EA%B8%B0">tar 아카이브의 내용 확인하기</a></td><td>tar tvf T.tar</td></tr><tr><td><a href="https://recipes4dev.tistory.com/146#37-%ED%98%84%EC%9E%AC-%EB%94%94%EB%A0%89%ED%86%A0%EB%A6%AC%EB%A5%BC-tar%EB%A1%9C-%EB%AC%B6%EA%B3%A0-gzip%EC%9C%BC%EB%A1%9C-%EC%95%95%EC%B6%95%ED%95%98%EA%B8%B0">현재 디렉토리를 tar로 묶고 gzip으로 압축하기</a></td><td>tar zcvf T.tar.gz *</td></tr><tr><td><a href="https://recipes4dev.tistory.com/146#38-gzip%EC%9C%BC%EB%A1%9C-%EC%95%95%EC%B6%95%EB%90%9C-tar-%EC%95%84%EC%B9%B4%EC%9D%B4%EB%B8%8C%EB%A5%BC-%ED%98%84%EC%9E%AC-%EB%94%94%EB%A0%89%ED%86%A0%EB%A6%AC%EC%97%90-%ED%92%80%EA%B8%B0">gzip으로 압축된 tar 아카이브를 현재 디렉토리에 풀기</a></td><td>tar zxvf T.tar.gz</td></tr><tr><td><a href="https://recipes4dev.tistory.com/146#39-%ED%98%84%EC%9E%AC-%EB%94%94%EB%A0%89%ED%86%A0%EB%A6%AC%EB%A5%BC-tar%EB%A1%9C-%EB%AC%B6%EA%B3%A0-bzip2%EC%9C%BC%EB%A1%9C-%EC%95%95%EC%B6%95%ED%95%98%EA%B8%B0">현재 디렉토리를 tar로 묶고 bzip2로 압축하기</a></td><td>tar jcvf T.tar.bz2 *</td></tr><tr><td><a href="https://recipes4dev.tistory.com/146#310-bzip2%EB%A1%9C-%EC%95%95%EC%B6%95%EB%90%9C-tar-%EC%95%84%EC%B9%B4%EC%9D%B4%EB%B8%8C%EB%A5%BC-%ED%98%84%EC%9E%AC-%EB%94%94%EB%A0%89%ED%86%A0%EB%A6%AC%EC%97%90-%ED%92%80%EA%B8%B0">bzip2로 압축된 tar 아카이브를 현재 디렉토리에 풀기</a></td><td>tar jxvf T.tar.bz2</td></tr><tr><td><a href="https://recipes4dev.tistory.com/146#311-tar-%EC%95%84%EC%B9%B4%EC%9D%B4%EB%B8%8C-%EB%AC%B6%EA%B1%B0%EB%82%98-%ED%92%80-%EB%95%8C-%ED%8C%8C%EC%9D%BC-%EB%B3%84-%EC%A7%84%ED%96%89-%EC%97%AC%EB%B6%80-%ED%99%95%EC%9D%B8%ED%95%98%EA%B8%B0">tar 아카이브 묶거나 풀 때 파일 별 진행 여부 확인하기</a></td></tr></tbody></table>

.
