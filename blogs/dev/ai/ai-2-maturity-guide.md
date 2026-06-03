---
title: "Using AI Well (Part 2) — How to Use It Well: Seven Maturity Stages"
labels: ["AI", "Using AI Well", "AI agent", "workflow", "automation", "developer productivity"]
published: false
date:
readerComments: "ALLOW"
bloggerPostId:
---

## Introduction

This is **Part 2 of the four-part "Using AI Well" series.**

- **Part 1** — *What* you can use: a map of the features and tools AI offers
- **Part 2 (this post)** — *How* to use it well: seven maturity stages
- **Part 3** — *Feeding AI well*: tokens (cost) and instructions (definition)
- **Part 4** — *Trusting what comes back*: verification and trust

Part 1 laid out "what you can use" — AI's models, core features, agents, multi-agent, skills, and plugins. Part 2's subject is the next question: **"So how should you use it well?"**

Few developers today answer "no" to "do you use AI?" But **how** they use it varies wildly from person to person and team to team. Some use it only for autocomplete; others hand an entire ticket-sized task to an AI agent. **This is exactly where results diverge even when everyone holds the same tools.**

This post organizes AI-usage maturity into **seven stages**, laying out how best to use AI at each one. These stages connect into a single **maturity ladder**, climbing in this order:

> using as a tool → delegating → automating → supervising → autonomy

The tools from Part 1 each find their place on this ladder. Check where you stand and think about how to climb the next rung.

## 1. Everyday Use — "Keep It Always On"

This is the stage where you keep tools like Copilot, Cursor, or Claude Code **on by default, not just when you happen to need them.**

- Beyond simple autocomplete, you use it as a **conversational work partner** — "refactor this function," "find the cause of this error."
- The starting point is replacing the back-and-forth between search box and docs with a flow of asking the AI and getting an answer.

The key is **making it a habit.** Your hand has to reach for AI naturally before the next stage opens up.

## 2. Verification — "Always Verify Generated Code"

The core of this stage is moving verification **from the human eye to an automated flow.** Code the AI writes isn't enough to just read through (review). Putting review + test + static analysis into a flow that **runs automatically**, so the machine catches what people miss, is the sign of maturity.

Underneath lies a shift in thinking.

> Not "the AI made it, so it's fast," but "the AI made it, so I verify it **more carefully**."

That's because AI will produce plausible-but-wrong code with a straight face. But **how far and how hard to verify** is a big enough topic that the final Part 4 covers it in depth. Here we'll only note that verification gets baked into the system rather than left to human willpower.

## 3. Delegation and Structured Input — "To Delegate Well, You Must Write Well"

This is the stage of **handing module- or feature-sized work to an AI agent wholesale, then always verifying the result before applying it.** It's where the **agent** from Part 1 (the AI that finds and reads files, fixes them, and even runs the tests on its own) really starts to shine.

The quality of delegation comes down to **how you structure the input.** Not a vague "do this thing," but the clearer you make the following four, the higher the hit rate of the output:

- **Input** — what context/data is given
- **Output** — what must be produced
- **Constraints** — the rules to honor (performance, style, dependencies, etc.)
- **Acceptance criteria** — what must be satisfied to count as "done"

It's exactly like delegating to a person: spell out the requirements clearly and the results improve. AI is no different.

## 4. Automation Pipelines and Tracking — "From Checklists to Automatic Gates"

- It's fine to start with **a checklist plus partial automation.**
- Gradually drive a **quality gate** into CI, so a merge is blocked when it falls below the bar.
- And leave AI's work results as **logs/reports/metrics.** Without tracking, there's no basis to judge "is the AI doing well?"

The **Skills** and **hooks** from Part 1 shine here. Bundle a repeated procedure into a skill and it runs at the same quality every time; hang a hook that fires at a certain moment (before a commit, after a task finishes) and verification and record-keeping leave human hands and dissolve into the pipeline.

Metrics worth keeping: number of auto-fixes, rework rate, review pass rate, change in test coverage.

## 5. AI-Led Development and Human Supervision — "From Author to Reviewer"

As you mature, **the AI drives development on a ticket basis** and the human's role shifts to **reviewer/supervisor.**

But it's not just handing off — a **system for supervising risk** is the premise.

- Document the review criteria and checklists
- Set **authority boundaries** like "changes of this kind require human approval"
- Reversible safety nets (rollback, staged rollout)

As you stop writing code directly, **judgment about what to let through and what to block** matters more.

## 6. Multi-Agent — "Split Roles, and Prepare for Conflicts"

This is the stage of putting the **multi-agent** introduced in Part 1 (the one that "eats ~15× the tokens but is powerful") into a real workflow. You split roles — say, a writer agent / reviewer agent / tester agent.

- At first it's normal for **a human to coordinate manually.** No need to aim for full automation at once.
- What matters is deciding **recovery procedures for conflicts and failures** in advance.

When agents' results clash or one stalls midway, it has to be clear **who or what intervenes** for real operation to be possible. Without that procedure, multi-agent quickly goes out of control.

## 7. Autonomy — "From Goal → Execute → Verify → Improve"

The final stage is the AI running the loop of **goal → execute → verify → improve** on its own. Further still, a level where it **measures outcomes and even proposes the next improvement.**

Realistic advice:

- Don't force full autonomy across every area.
- Apply the autonomous loop **starting from a narrow, verifiable area.**
- Outcome evaluation is still best done by a human.

Autonomy is a process of widening "the range it's safe to entrust" one rung at a time — not a switch that hands over everything at once.

## Wrapping Up

The one principle running through these seven stages:

> **Don't delegate without verification, don't automate without structure, and don't go autonomous without supervision.**

Don't skip stages; climb to the next only after **putting that stage's safety nets in place first.** That's the key to using AI fast and, above all, **safely.**

The tools from Part 1 (models, agents, multi-agent, skills, plugins) are ultimately the footholds for climbing this ladder one rung at a time. Real productivity comes where **knowing the tools (Part 1)** meets **using them maturely (Part 2).**

Take a look at roughly which stage your way of working sits at, and what the next rung is.

But as you climb this ladder, everyone hits two walls: **"why is this costing so much?" (tokens)** and **"why won't it do what I told it?" (instructions).** **Part 3** tackles these two axes head-on, and then **Part 4** wraps up the series with how to trust and verify what you get back.
