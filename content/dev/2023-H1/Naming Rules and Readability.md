---
title: "Naming Rules and Readability"
labels: ["Archive"]
published: true
date: 2023-04-27T10:00:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "4483666589118093072"
source: "blogger"
sourceBlog: "https://ten-logged.blogspot.com/"
sourcePostId: "622890972721841997"
sourceStatus: LIVE
sourceUrl: "https://ten-logged.blogspot.com/2023/04/test.html"
sourcePublishedAt: "2023-04-27T18:06:00-07:00"
---
#### Things to keep in mind when naming variables, classes, files, and so on

#### 

Readability  
It's best if you can tell what something does from its name alone.  
Use prefixes well.  
Confusion  
Keep scopes small to avoid declaring duplicate variables (lots of globals is bad).  
Reassigning all sorts of values to one variable is bad (it gets confusing).  
Style  
Decide up front where to use camelCase, PascalCase, and so on: classes, interfaces, etc.

#### Prefix Types

#### 

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

This is apparently Google's code style guide. It should be a helpful reference.  
[https://google.github.io/styleguide/](https://google.github.io/styleguide/)
