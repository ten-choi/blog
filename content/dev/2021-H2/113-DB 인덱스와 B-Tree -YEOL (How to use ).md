---
title: "DB 인덱스와 B-Tree (How to use)"
labels: ["DB","rdb","B-tree","SQL"]
published: false
date: 2021-12-13T15:39:10+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 113
tistoryUrl: "https://yeolceo.tistory.com/113"
tistoryCategory: "DB/rdb"
tistoryTags: ["B-tree","SQL","DB"]
tistoryPostedAt: "2021-12-13 15:39:10"
language: ko
bloggerPostId: "6735386224323188082"
---
사전 단어 설명

Full Scan : 테이블에 포함된 레코드를 처음부터 끝까지 읽어들인다.

```html
explain SELECT * FROM 테이블명;
```

Range Scan : 테이블의 일부 레코드만 읽어들인다.

```html
explain SELECT * FROM 테이블명 where no > 1 and no < 5;
```

index Scan : (인덱스 컬럼을 등록했다면 ) 인덱스를 기준으로 조건문을 호출하여 레코를 호출합니다. 

```html
explain SELECT * FROM 테이블명 where 인덱스컬럼 = '비교값'
```

Duration : 쿼리를 실행할때 걸리는 시간입니다. 최소화 할수록 성능에 도움이 됩니다.

Fetch : 쿼리의 결과값을 가져오는데 사용한 시간입니다. 네트워크 성능에 따른 시간을 나타냅니다.

### **인덱스란**

RDBMS를 사용할때 검색 성능을 향상시키는 기술중 하나입니다. 키값을 기초로 정렬하여 정렬된 데이터를 검색하기에 성능이 향상됩니다.

Index 없이 Select와 Where 절을 사용하면 Full Scan을 하게됩니다. 하지만 Index를 적용한다면 Index Range Scan을 통해 검색하기때문에 검색영역 범위 차이가 적어져 속도가 향상됩니다. 단 일정 양을 넘어간다면 풀스캔이 좋을수도있음

장점

1.  SQL문을 변경하지 않아도 성능 개선을 할 수 있다. 
2.  테이블의 데이터에 영향을 주지 않는다. 
3.  일정한(때로는 극적인) 효과를 기대할 수 있다. 

**단점**

하지만 데이터 변경이 자주일어난다면 insert의 경우 기존index에 index를 리빌드 해야해서 성능에 영향을 끼친다.

index를 리빌드 db의 성능에 포함되기때문에 남용할경우 부하를 초래합니다.

만들때 필요한 기준

**1\. 크기가 큰 테이블만 만든다.** 

**3\. Cardinality(카디널리티)가 높은 열에 만든다.** 

### **B-Tree (Balanced Tree)인덱스**

최상위에 루트 노드가 존재하고 그아래 브랜치노드가 뻗어나갑니다. 최하위노드를 리프노트 라고 부릅니다. 

인덱스와 실제 데이터가 저장된 데이터는 따로 관리 되는데, 인덱스의 리프노드는 항상 실제 데이터 레코드를 찾아가기 위한 주소값을 가지고있습니다.

저장될위치가 결정되면 레코드의 키값과 대상레코드의 주소 정보를 B-Tree 의 리프노드에 저장합니다. 만약리프노드가 꽉 차서 더는 저장할 수 없을때 는 리프노드가 분리 돼야하는데 이는 상위 브랜치 노드까지 범위가 넓어집니다. 그래서 쓰기작업에 비용이 많이 듭니다. 

### **사용법**

ex를 생성하는것도 db의 성능에 포함

테이블에 인덱스가 있나 보기

```html
show index from 테이블명;
```

테이블에 인덱스 추가하기 

```html
create index testindex on  WORK_DAILY_SEQ (CAR_NUM);
ALTER TABLE 테이블명 ADD INDEX 인덱스컬럼명 USING BTREE (인덱스할컬럼);
```

```html
ALTER TABLE 테이블명 ADD INDEX 인덱스컬럼명 USING BTREE (인덱스할컬럼);
```

```html
ALTER TABLE 테이블명 ADD INDEX 인덱스컬럼명 USING BTREE (인덱스할컬럼);
```

```html
ALTER TABLE 테이블명 ADD INDEX 인덱스컬럼명 USING BTREE (인덱스할컬럼);
```

### **인덱스 실행시**

인덱스를 실행하면 인덱스를 걸고 스캔한것과 일반 레인지 스캔 그리고 풀스캔 할때 

### **인덱스 리빌드**

검색 이외의 인서트 업데이트 딜리트를 하다보면 트리의 한쪽이 무거워져서 성능 저하로 이어질수있다고합니다.

검색과정에서 속도가 저하되기 때문에 리빌딩 작업이 주기적으로 필요하다합니다.

인덱스를 그냥 배열로 안하는이유

![출처 https://www.geeksforgeeks.org/search-insert-and-delete-in-a-sorted-array/](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/113/img.webp)

참고사이트

[https://zorba91.tistory.com/292](https://zorba91.tistory.com/292)
