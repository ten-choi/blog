---
title: "[ Django ] orm 참조 역참조"
labels: ["Python","django"]
published: false
date: 2023-03-13T17:57:11+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 160
tistoryUrl: "https://yeolceo.tistory.com/160"
tistoryCategory: "Python/django"
tistoryTags: []
tistoryPostedAt: "2023-03-13 17:57:11"
language: ko
bloggerPostId: "2577826967498506386"
---
#### ? **환경** 

Python 3.8  
VsCode

#### ? **개요**

#### ? **목차**

## **\- Django orm 참조**

정참조

1. 

```python
db.SomeModel.objects.select_related('SomeModel에서 참조하고있는 fk 컬럼').get(조건문)

e.g)
db.Account.objects.select_related('fk_id')filter(user_account='abc')
```

2. 

```python
db.SomeModel.objects.filter(
fk_some_column_id__index = "1"
)
```

역참조

```python
instance = (
    db.Acount.objects.filter(
        index=params["fk_id"]
    )
)
card_info = db.Card.objects.filter(
    index=Subquery(
        instance.values("fk_card__id")[:1]
    )
)
```

역참조를 subquery를 통해서 하고 save로 저장 할경우 외래키 에러가 나옵니다

그래서 update구문으로 진행해줘야합니다

추가적으로 작성 필요한경우 수정및 작성 예정

**? 근거 있는 조언은 언제나 환영합니다. 성실한 코딩 하세요.**
