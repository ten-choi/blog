---
title: "[ Git ] Designing a Git Workflow When Starting a Project"
labels: ["ETC","Git","Archive"]
published: true
date: 2022-08-22T17:38:50+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 144
tistoryUrl: "https://yeolceo.tistory.com/144"
tistoryCategory: "ETC/Git"
tistoryTags: ["git","git","git"]
tistoryPostedAt: "2022-08-22 17:38:50"
language: en
bloggerPostId: "6267284894056286048"
---
#### ? **Environment**

#### ? **Overview**

Designing how to use git with readability, efficiency, and so on in mind!

#### ? **Contents**

-   Initial git setup
-   git flow branches
-   issue, bug, pr

## **\- Initial Git Setup**

1.  Create the git project
2.  Create bug and feature issue templates for it (see images)
3.  Clone it with a git tool  
    If you have two accounts, add the second one in settings (I use the Fork git tool)
4.  Create a branch named prod and use that branch  
    Add dev and feature branches later; staging is optional

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/144/img_1.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/144/img_2.webp)

## **\- Git Flow Branches**

These are the branches I'll use. Add or remove them as needed.  

1.  prod: the branch for the service actually deployed
2.  dev: the pre-release test branch that receives PRs from feature branches
3.  feature-issue#1: a branch created when adding a new feature, named with the git issue number
4.  hotfix-issue#1: a branch created when something breaks in prod
5.  staging: a branch for testing in the environment closest to prod  
    (this branch can lose its point if a third party returns different values for prod and dev, or if testing is only possible on dev)

The order is feature -> dev, hotfix -> prod, with prod as the top-level branch.  
You send a PR from a lower branch to a higher one, test it, and then send a PR further up. When something is partially fixed in hotfix or dev,  
use rebase so the existing branches follow the updated base.

## **\- issue, bug, pr**

Documentation like issues, bugs, and PRs is managed on the project's git web page.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/144/img_3.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/144/img_4.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/144/img.webp)

For issues, always make use of the number assigned when the issue is created.

**? Well-grounded advice is always welcome. Happy coding, and keep at it.**
