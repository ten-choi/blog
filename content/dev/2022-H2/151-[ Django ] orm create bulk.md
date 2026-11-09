---
title: "[ Django ] orm create bulk"
labels: ["Python","django","bulk","create","orm"]
published: true
date: 2022-12-27T16:40:11+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 151
tistoryUrl: "https://yeolceo.tistory.com/151"
tistoryCategory: "Python/django"
tistoryTags: ["bulk","create","orm"]
tistoryPostedAt: "2022-12-27 16:40:11"
language: ko
bloggerPostId: "7075668566141505540"
---
#### ? **환경** 

Python 3.8  
VsCode

#### ? **개요**

Django orm을 사용해서 create가 여러 번일 때 bulk로 한 번에 진행합니다.

#### ? **목차**

-   bulk란

## **\- bulk란**

다수의 레코드를 생성, 업데이트해야 할 경우 한 번의 커넥션으로 수행하는 기능입니다.

사용 이유는 포문으로  커넥션을 여러 번 해서 생성, 업데이트를 하면 시간복잡도가 증가합니다. 

레이지 로딩이라고 쳐도 db와 커넥션 되는 orm이나 쿼리를  2~N 번 돌려야 하는 것부터 **latency**에 시작이라고 볼 수 있습니다.

```python
for i in range(100):
	some_model.objects.create(name= 'name')
```

같은 100번의 시간복잡도라도 자체적으로 데이터를 만들고 bulk를 이용해 한번에 생성하면 성능 향상에 훨씬 도움이 됩니다.

```python
for i in range(100):
	names.append(some_model(name = i))

db.objects.bulk_create(names)
```

**? 근거 있는 조언은 언제나 환영합니다. 성실한 코딩 하세요.**
