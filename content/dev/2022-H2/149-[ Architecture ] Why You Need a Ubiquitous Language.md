---
title: "[ Architecture ] Why You Need a Ubiquitous Language"
labels: ["Architecture","ubiquitous","Archive"]
published: true
date: 2022-11-14T18:34:42+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 149
tistoryUrl: "https://yeolceo.tistory.com/149"
tistoryCategory: "Architecture/architecture"
tistoryTags: ["architecture","ubiquitous"]
tistoryPostedAt: "2022-11-14 18:34:42"
language: en
bloggerPostId: "6675237322911384174"
---
A ubiquitous language is a shared vocabulary that everyone on a project uses the same way: developers, architects, planners, designers, and so on.

### Why do we need a ubiquitous language?

It minimizes miscommunication between members of an organization or company working on the same project.

What does that mean? Take the words "product" and "food." At a food company, both of the following might be used to mean the same thing:  
e.g.)  
\- Sales of our food  
\- Sales of our products

They sound similar, but they're clearly different words. If you lose the thread of a meeting even once and miss the exact intent,  
you can get confused when "product" ends up meaning something other than food.  
The same problem shows up in development when several people work on one project and declare variables.  
If cost is expressed in different ways, like below:  
e.g.)  
\- cost  
\- price

Cost and price are similar but ambiguously different. That leaves room for confusion.  
So if you use a common vocabulary that everyone understands precisely, you minimize the chance of problems.

This matters for any company, and it matters even more when you split one service into multiple domains, as in an MSA architecture.  
You need to prevent cases where other teams or partner companies use the same term with a different meaning.

### How should you organize it?

Put the shared vocabulary somewhere everyone can see it, using Notion or another collaboration tool.  
Have developers, planners, architects, and others build it together: the English term to use for variable names, the Korean term,  
and a description. That's all it takes for a basic glossary.

It doesn't have to look exactly like the example below, but it's important to set your own rules and keep updating it.

-   Category 1 - (category) - term (English), term (Korean), description
-   Category 2 - (category) - term (English), term (Korean), description
-   Category 3 - (category) - term (English), term (Korean), description

It's best to start early, before the business or project grows complex.  
The key is to share it with everyone and keep aligning on the words you use.  
Even in meetings, keep using existing and new terms with their exact intended meaning.
