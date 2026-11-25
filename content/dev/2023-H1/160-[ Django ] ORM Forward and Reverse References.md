---
title: "[ Django ] ORM Forward and Reverse References"
labels: ["Python","django","Archive"]
published: true
date: 2023-03-13T17:57:11+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 160
tistoryUrl: "https://yeolceo.tistory.com/160"
tistoryCategory: "Python/django"
tistoryTags: []
tistoryPostedAt: "2023-03-13 17:57:11"
language: en
bloggerPostId: "2577826967498506386"
---
#### ? **Environment** 

Python 3.8  
VsCode

#### ? **Overview**

#### ? **Contents**

## **\- Django ORM References**

Forward reference

1. 

```python
db.SomeModel.objects.select_related('fk column referenced by SomeModel').get(condition)

e.g)
db.Account.objects.select_related('fk_id').filter(user_account='abc')
```

2. 

```python
db.SomeModel.objects.filter(
fk_some_column_id__index = "1"
)
```

Reverse reference

```python
instance = (
    db.Account.objects.filter(
        index=params["fk_id"]
    )
)
card_info = db.Card.objects.filter(
    index=Subquery(
        instance.values("fk_card__id")[:1]
    )
)
```

If you do a reverse reference through a subquery and then save with `save`, you get a foreign key error.

So you need to use an `update` statement instead.

I'll revise and add more if needed.

**? Well-grounded advice is always welcome. Code with care.**
