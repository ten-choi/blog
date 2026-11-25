---
title: "[ Django ] Bulk Create with the ORM"
labels: ["Python","django","bulk","create","orm","Archive"]
published: true
date: 2022-12-27T16:40:11+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 151
tistoryUrl: "https://yeolceo.tistory.com/151"
tistoryCategory: "Python/django"
tistoryTags: ["bulk","create","orm"]
tistoryPostedAt: "2022-12-27 16:40:11"
language: en
bloggerPostId: "7075668566141505540"
---
#### ? **Environment** 

Python 3.8  
VsCode

#### ? **Overview**

When you need to create many records with the Django ORM, do it in one go with bulk.

#### ? **Contents**

-   What is bulk

## **\- What Is Bulk**

It's a feature that creates or updates many records over a single connection.

Why use it? If you create or update records in a for loop, opening a connection each time, the time complexity goes up. 

Even with lazy loading, having to run an ORM call or query against the DB 2 to N times is where **latency** starts.

```python
for i in range(100):
	some_model.objects.create(name= 'name')
```

Even with the same 100 iterations, building the objects yourself and creating them all at once with bulk helps performance a lot.

```python
for i in range(100):
	names.append(some_model(name = i))

db.objects.bulk_create(names)
```

**? Well-grounded advice is always welcome. Code with care.**
