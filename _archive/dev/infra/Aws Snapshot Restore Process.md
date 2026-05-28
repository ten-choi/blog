---
title: "Aws Snapshot Restore Process"
labels: ["aws rdb", "snapshot restore"]
date: 2023-05-21T21:08:00-07:00
bloggerPostId: "6214511176349014941"
published: true
originalUrl: "https://ten-logged.blogspot.com/2023/05/aws-snapshot-restore-process.html"
---
#### **Topic: How to restore rdb from snapshot**

aws rds에는 매일 자동으로 백업하는 시스템이 있다  
그 백업 데이터를 snapshot이라고 부른다  
그러면 snapshot으로 백업해 놓은 rdb정보를 되살리려면 어떻게 해야 할까?  
aws의 rds설정을 찾아보자

![](https://blog.kakaocdn.net/dn/llNo8/btsgC48elzA/spfluWoZdeeMvzOm62SkzK/img.png)

  

위 이미지 왼쪽 카테고리에 snapshot을 클릭하자  
자동으로 생성된 snapshot들의 list가 존재한다

![](https://blog.kakaocdn.net/dn/cvKNrt/btsgL9GTW6X/ZFGosezZjDmrJXvCVQw3bK/img.png)

  

오른쪽 버튼을 통해 snapshot 복원을 클릭한다  

![](https://blog.kakaocdn.net/dn/ylE5p/btsgKpwezK1/RCn12P9taXSa9ax6DSekLk/img.png)

  

정해져 있는 설정은 그대로 따라가면 된다  
rdb version은 내가 복구하려는 rdb와 동일하게 설정하자

![](https://blog.kakaocdn.net/dn/btnzug/btsgJ1h5Bk4/mRsQ5OAKtpmqEzoPzJ6YPk/img.png)

위의 public access에 예를 꼭 해줘야 한다  
안 하면 ec2를 제외한 외부에서 접근이 안된다

이후 default 그대로 진행하며  
최하단 버튼인 클러스터 복원 버튼을 누르면 끝이다

새로운 rdb instance가 생성된다  
snapshot에 저장된 백업 데이터가 해당 instance에 들어있다  
instance 생성되는데 오래 걸리니까 실수 없게 진행하는 것이 좋다

위의 처리대로 잘 진행했다면 주의사항이 있다

1.  amazon s3로 내보내기라는 버튼이 있다  
    사용하지 말자  
    해당 기능은 s3에 Parquet(파케이) 파일 형식으로 데이터를 export 한다  
    export 할 때 시간도 오래 걸리고 해당 파일 쓰기도 복잡하다
2.  snapshot list를 보면 하나의 row가 업데이트되는 방식이다  
    다음날 덮어쓰기 되니까 미리 카피 떠놓고 진행하자 
3.  생성하고 데이터를 얻었으면 바로 rds를 삭제하자  
    요금이 나온다
