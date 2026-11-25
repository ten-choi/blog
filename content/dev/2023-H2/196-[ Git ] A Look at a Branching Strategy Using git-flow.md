---
title: "[ Git ] A Look at a Branching Strategy Using git-flow"
labels: ["ETC","Git","Strategy","GitHub","git-flow","Archive"]
published: true
date: 2023-12-13T17:39:13+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 196
tistoryUrl: "https://yeolceo.tistory.com/196"
tistoryCategory: "ETC/Git"
tistoryTags: ["Strategy","KR","GitHub","git-flow"]
tistoryPostedAt: "2023-12-13 17:39:13"
language: en
bloggerPostId: "8766786131329149289"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/196/img.webp)

## **Why We Adopted git-flow**

With the team steadily growing, we felt the need to get a version control strategy in place.

The more people we added, the more we needed a git strategy suited to a larger team working in parallel.

So we decided to get familiar with it early, getting over the learning curve ahead of time so it would settle in naturally later.

## **git-flow Branch Structure**

1.  master  
    The branch used for the actual product; it only holds deployable states.
2.  develop  
    The main branch during development.  
    It's the base for creating feature and release branches.
3.  feature  
    A branch for developing a new feature. Once the feature is done, merge it into develop; if it's no longer needed, discard it.  
    \- Base branch: develop  
    \- Merges into: develop
4.  release  
    A development branch for final testing and bug fixes before deploying the next version.  
    \- Base branch: develop  
    \- Merges into: develop, master
5.  hotfix  
    A branch created from master when a deployed version needs an urgent fix.  
    \- Base branch: master  
    \- Merges into: develop, master

## How the Git-flow Works

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/196/img_3.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/196/img_4.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/196/img_5.webp)

#### Starting New Work

1.  Create an Issue in the project on GitHub.
2.  Fill in the Title and Content with the work to be done.
3.  Set the tags in the right sidebar.  
    \- Tag yourself under Assignees  
    \- Tag Feature under Labels  
    \- Tag which project you're working in under Project  
    \- Tag whether it's a PR or a regular Issue under Milestone
4.  Once it's created, an Issue number is generated automatically. Use it in the feature branch name.
5.  Create a new branch from develop, combining feature with the Issue number, e.g. feature-issue#3303,  
    and do your work there.

When the work is done

1.  Create a PR in the project on GitHub.
2.  Set develop as the base branch to merge into, and feature-issue#xxxx as compare.
3.  Fill in the Title and Content with the work done.
4.  Set the tags in the right sidebar.  
    \- Tag the people who'll review it under Reviewers  
    \- Tag yourself under Assignees  
    \- Tag Feature and a D-n (review-by deadline) under Labels  
    \- Tag which project you're working in under Project  
    \- Tag whether it's a PR or a regular Issue under Milestone  
    \- Find and link your Issue under Development
5.  The PR goes through code review, and the reviewer does the merge.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/196/img_1.webp)

#### When It's Time to Deploy

1.  Locally, create release-v\[current version number+\] as a new branch from develop.
2.  Create a PR in the project on GitHub.
3.  Set master as the base branch to merge into, and the release branch as compare.  
    (Check the project's current version on GitHub and version the branch accordingly.)
4.  Fill in the Title and Content with the work done.
5.  Set the tags in the right sidebar  
    \- Tag yourself under Assignees  
    \- Tag Release under Labels  
    \- Tag which project you're working in under Project  
    \- Tag whether it's a PR or a regular Issue under Milestone  

6.  Once the release branch passes its final check, merge it on GitHub.  
    It's deployed automatically via GitHub Actions.
7.  If the release branch has changes, merge it into develop too, then delete the release branch.

Release version notation

-   Release Number: Starts at 1. Bump it by 1 when the project goes through a drastic change.
-   Major Number: Starts at 0. Bump it by 1 when a major feature is added or changed.
-   Minor Number: Starts at 0. Bump it by 1 for small changes like bug fixes.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/196/img_2.webp)

#### When You Need a Hotfix

1.  Locally, create hotfix-\[current version number\] as a new branch from master.
2.  Fix what needs fixing.
3.  Create a PR on GitHub.
4.  Set master as the base branch to merge into, and hotfix-v1.23.4 as compare.
5.  In the title, write what the PR is for.
6.  Describe the changes in the content.
7.  Set the tags in the right sidebar  
    Tag yourself under Assignees  
    Tag the branch type under Labels, e.g. Hotfix  
    Tag which project under Project  
    Tag whether it's a PR or an issue under Milestone
8.  Once final testing is done, merge it on GitHub.
9.  If there were changes, merge into develop too and delete the branch.
10.  It's deployed to prod via GitHub Actions.

## After Deploying

Update the release notes with the work time, task list, version, and so on, and post them in a shared messenger like Slack so the team can see.

I plan to revise this strategy and write about it again later.
