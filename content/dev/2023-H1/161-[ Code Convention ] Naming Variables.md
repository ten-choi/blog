---
title: "[ Code Convention ] Naming Variables"
labels: ["Variable Names","Prefixes","Variables","Archive"]
published: true
date: 2023-04-20T13:02:34+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 161
tistoryUrl: "https://yeolceo.tistory.com/161"
tistoryCategory: ""
tistoryTags: ["변수명","접두어","변수"]
tistoryPostedAt: "2023-04-20 13:02:34"
language: en
bloggerPostId: "684730880815330605"
---
#### ? **Overview**

Let's come up with nice variable names.

## **\- Variable Readability**

I think a variable is most readable when you can tell what it does from its name alone, without any comments.

Using prefixes well makes your variable names much more effective.

-   is + word: returns a boolean for whether something is ~  
    e.g.) isValid: is this valid?
-   can + word: returns a boolean for whether ~ is possible  
    e.g.) canRead: can it be read? (permission)
-   has + word: returns a boolean for whether it has ~  
    e.g.) hasItem: does it have that item?
-   on + word: returns a ~ boolean  
    e.g.) onClick: was the button clicked?

get, put, create, req, num, count, min, max, input, output, temp, dir  
prev, curr, next, last, init, def 

**? Well-grounded advice is always welcome. Code with care.**
