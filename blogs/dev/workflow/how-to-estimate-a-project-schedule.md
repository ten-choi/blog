---
title: "How to Estimate a Project Schedule - A Logical Approach"
labels: ["project estimation", "project management", "software planning", "PERT", "CPM"]
published: true
date:
readerComments: "ALLOW"
bloggerPostId: "323490085119896229"
---

# How to Estimate a Project Schedule - A Logical Approach

When you work at a company, requests come at you. You rarely get a proper SRS document — usually it's just "we want to build something."

Sometimes the request shows up without any planning at all, and you end up doing the planning yourself. Then the question comes: "When can you have it done?"

Estimating a schedule is the same whether you're the CEO or a brand-new hire. Both sides need to think about the timeline together. Let me walk through an example.

Say someone tells you: "Starting today, you need to build a car." What do you do?

You need to figure out what you're actually building. Without a clear understanding of the work, you can't estimate anything. To respond to a "when can you ship it?" with something better than a guess, you need a logical process.

Methodologies like PERT or CPM are worth knowing. But the point here isn't to wear an off-the-rack suit — it's to tailor one to your project.

## The Agenda

Before committing to a date, answer these in order:

1. How much time was given to you?
2. Is the problem clearly defined?
3. Are there unknowns inside the definition?
4. How long will the work itself take?
5. Will other work land on you in parallel?
6. Are other people involved, and does your timeline depend on them?

Let's run through this from a backend developer's perspective.

A request comes in: "We have lots of branch offices, and we want a multi-tenant message board our staff can use."

A developer is going to have questions:

1. Do user accounts already exist?
2. Multi-tenant — but should any tenants be able to share a board?
3. Should admins be able to see every board?
4. Are nested replies allowed indefinitely?
5. Can users upload images?

Why does the order on the agenda matter? Because the first question is always: **by when does this need to be done?**

If you treat hours as cost, the CEO is effectively saying "I want to buy a website for X amount of money." So your response is obvious: "How much budget were you thinking?"

## Walking Through an Estimate

Let's say the CEO has 4 months of budget. Call that 18 weeks. Is it feasible?

Now you start working through the agenda. Don't commit to a date before items 2–6. Saying "yes" too fast is how you end up missing deadlines or living at the office.

### Get a budget for the estimate itself

Take a week to actually estimate the project.

```
allWeek: 1
```

The size of this estimation budget should match the project. If you're new to the domain, give yourself more — make a rough guess and refine it.

### Item 2 — Define the problem

Problem definition usually eats the most time. This is when you're asking questions: what's needed, and how much of it.

If requirements aren't going to thrash, my preference is to do API definition and DB design at the same time as problem definition.

If this is a brand-new project, you also need to:

- Split the domain
- Decide on the source code file structure
- Set the Git Flow policy
- Wire up CI/CD (GitHub Actions, AWS, etc.)
- Establish the ubiquitous language

This setup costs about another week.

```
allWeek: 2
```

Design the URL layout, request/response shapes for each API in a tool like Postman. For the database, identify the domain entities and the columns. Tools like aQueryTool or erdCloud help here.

By the time you're done with item 2, the DB design is settled. Say you end up with 25 APIs. Assume each takes about 2 days. For a single API the flow is:

1. API adapter
2. Service logic
3. Persistence
4. Swagger / documentation for the frontend
5. Validation
6. Code review and cleanup

That's 10 weeks of work.

```
allWeek: 12
```

### Item 3 — Unknowns

Item 2 is wrapped up cleanly. Now factor in uncertainty. Some features might take longer than estimated — note that explicitly.

Your estimate becomes a min/max range, not a single number. If something is genuinely "we'll know once we try it," say so. Let's add a week for unknowns.

```
allWeek: 13
```

### Item 5 — Other work

Suppose another three weeks of unrelated work lands on you mid-project.

```
allWeek: 16
```

### Item 6 — Dependencies on others

Now think about the frontend. They can do whatever doesn't require the API while waiting, and you'll share API docs incrementally. Even with overlap, expect about 2 more weeks after the APIs are done.

```
allWeek: 18
```

### Testing

Two weeks of testing.

```
allWeek: 20
```

## Bringing It Back

So: starting from the kickoff, the first week is estimation. Then you go back to the CEO or PM with: "Including the estimation week, I'm at a 20-week plan. Is that okay?"

Now you negotiate. What can we cut to hit the date? Does this need overtime? That conversation is the point.

If it ends cleanly at 20 weeks, great — you've got your plan.

## After the Plan

If the project doesn't go the way you scoped it, you iterate. Schedules are anchored to *your* capability, and that takes time to calibrate. The important thing is to keep trying — each project sharpens the next estimate.
