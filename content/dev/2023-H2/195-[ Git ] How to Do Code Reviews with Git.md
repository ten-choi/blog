---
title: "[ Git ] How to Do Code Reviews with Git"
labels: ["ETC","Git","code","Archive"]
published: true
date: 2023-10-17T15:52:24+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 195
tistoryUrl: "https://yeolceo.tistory.com/195"
tistoryCategory: "ETC/Git"
tistoryTags: ["KR","Git","code"]
tistoryPostedAt: "2023-10-17 15:52:24"
language: en
bloggerPostId: "3408747848463356036"
---
Terms

-   Reviewer: someone who reviews code written by others
-   Reviewee: someone whose code is being reviewed by others
-   PR: short for GitHub Pull Request
-   LGTM: short for Looks Good To Me

## About Code Review

Code review is when reviewers and reviewees exchange feedback in an agreed-upon way.

Since code review is a form of feedback, I recommend setting a policy for it, something like [Netflix's 4A](https://brunch.co.kr/@brunchnopu/9).

Code review has these benefits:

1.  Others can catch mistakes you missed.
2.  Code conventions stay consistent, which raises code quality.
3.  You learn from reading other people's code and can apply it to your own work.

## Asynchronous Communication

Code review works better as asynchronous communication.

Synchronous communication means the reviewer and reviewee find a time to sit down and go through the code together.

Looking at it together has its upsides, of course, but it's less efficient.

Asynchronous communication is like sending a message that says, "I've reviewed your code, take a look whenever you like."

You set a deadline and let each person review on their own time during work hours, so everyone can focus better on their own tasks.

That's also why we use GitHub as the tool: it makes asynchronous code review easy.

## D-n: Helping Prioritize Reviews

The reviewee should set a deadline for when they'd like their PR reviewed.

As PRs pile up, without priorities developers will have a hard time deciding what to handle first.

When you create a PR on GitHub, there's a Labels section in the right sidebar.

When requesting a review, mark the date you want it reviewed by with a label like D-0, D-2, and so on.

-   D-0: Please review as soon as possible
-   D-1: Please review by tomorrow
-   D-N: From the day after tomorrow on, set it as the situation requires

## Importance of Reviewer Comments

We borrow the P from "priority." Priorities run from 1 to 5, and the lower the number, the more important it is.

1.  P1: Must be addressed (Request changes)  
    When the reviewer judges that the PR must be fixed because it could cause a serious error in the service, they use the P1 tag to request changes from the reviewee. The reviewee must either apply the request or convince the reviewer why they can't.  

2.  P2: Please seriously consider this (Request changes)  
    For P2, the reviewee should accept it, or if they can't, a reasonable discussion is encouraged.  

3.  P3: Please address this if you can (Comment)  
    For P3, the reviewee should accept it, or if they can't, explain why or explicitly leave a concrete plan to address it later.  

4.  P4: Fine either way (Approve)  

5.  P5: Just a minor opinion (Approve)  
    A minor opinion from the reviewer. It's fine to ignore it.

```typescript
e.g) P4: The convention here differs from the existing code. Is there a reason?
```

## Code Review Flow

1.  The reviewee requests a code review from the reviewer with a D-n tag saying when it's needed by.
2.  The reviewer checks the deadline and does the review during their working hours.
3.  The reviewee replies to the review comments, or for simple fixes, leaves a thumbs-up emoji to show they've seen it.
4.  When the reviewer considers the review finished, they comment LGTM.
5.  Once every reviewer has left LGTM, the last reviewer merges.

## References

1.  [Banksalad tech blog](https://blog.banksalad.com/tech/banksalad-code-review-culture/)
2.  [Kakao tech blog](https://tech.kakao.com/2022/03/17/2022-newkrew-onboarding-codereview/)
