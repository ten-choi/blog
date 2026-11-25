---
title: "How to Start from Customer Requirements"
labels: ["Archive"]
published: 
date:
readerComments: ""
language: en
bloggerPostId: ""
---

 

Customer requirements
"Users should be able to browse shows and seats, pick the seats they want, and pay."
"It's usually quiet, but right after tickets open, hundreds of thousands of people could come in at once."
"The same seat must never be sold to two people."
"Even when traffic spikes, we'd rather the whole service not go down."
"We don't want users waiting too long."
"It has to integrate with the membership system and payment system we use today, as they are."
"The DB will be our existing PostgreSQL, and the infrastructure will be AWS."
"We plan to use this system for other shows going forward."

Functional requirements
Browse shows/seats, select seats, confirm booking, payment

Quality requirements
Hundreds of thousands of connections at the moment of opening -> scalability, performance
Stay up even under a rush -> availability
Don't make people wait long -> performance
Will be used for other shows too -> modifiability

Core rule (non-negotiable)
Zero double-sold seats

Constraints
Existing payment system, existing membership system, PostgreSQL, AWS-based development




Resolving ambiguity

-> "I think hundreds of thousands of people will rush in."
What was the peak in the last two years? What's the maximum number of tickets that can be issued?
-> "I think it was about 600,000."
Then roughly 600,000 people could hit the system right after opening.
@Right after opening, about 600,000 users could hit the server within one second

-> "It'd be frustrating if users had to wait too long."
All at once


