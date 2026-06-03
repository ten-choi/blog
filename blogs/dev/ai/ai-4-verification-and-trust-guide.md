---
title: "Using AI Well (Part 4) — How to Trust What Comes Back: Verification and Trust"
labels: ["AI", "Using AI Well", "verification", "code review", "testing", "developer productivity"]
published: false
date:
readerComments: "ALLOW"
bloggerPostId:
---

## Introduction

This is **Part 4 — the final installment — of the four-part "Using AI Well" series.**

- **Part 1** — *What* you can use: a map of models, features, agents, skills, plugins
- **Part 2** — *How* to use it well: seven maturity stages
- **Part 3** — *Feeding AI well*: saving tokens (cost) and sharpening instructions (definition)
- **Part 4 (this post)** — *How to trust what comes back from AI*: verification and trust

Through Part 3, it was essentially a story about **input** — what, how much, and how well to feed in. But feeding it well isn't the end. **Whether you can trust what comes back** is an entirely different problem.

When AI doesn't know, it doesn't say "I don't know." It **hands you a wrong answer with full confidence.** So as much as the skill of refining input, you need the skill of **doubting and verifying the output.** That's the subject of this post.

## Hallucination — "Why It's Confidently Wrong"

### Plausible and Correct Are Different Axes

What AI produces is optimized for **plausibility**, not guaranteed **correctness.** The two usually travel together, but the moment they diverge is the problem.

- Calling a nonexistent API/function/option **as if it exists**
- Presenting actually-wrong numbers/dates/sources **in a confident tone**
- Making subtly-off logic **slip by** because it reads naturally

The most dangerous isn't the "blatantly wrong answer" but the **"90% right, 10% wrong answer."** It's plausible enough that you skip verification, and that 10% blows up later.

### So Flip Your Thinking

The principle we touched in Part 2, stage 2 — here we bring it back as the core of the series.

> Not "the AI made it, so it's fast," but **"the AI made it, so I verify it more carefully."**

The speed gain comes from **generation**, not from skipping verification. Time saved by cutting verification comes right back as rework — and as we saw in Part 3, rework leaks tokens too.

## The Ladder of Verification — From Light to Heavy

Verification has stages too. You don't need maximum intensity on every result — pick **in proportion to the risk.**

### Stage 1: Reading (review) — Cheapest but Weakest

Just reading it yourself. Fast and free, but **people are good at waving plausible code through.** AI code especially fools you because its syntax and style are clean. Reading is just a start; don't stop here.

### Stage 2: Automated Verification (test · static analysis) — Let the Machine Catch It

- **Test** — confirm by actually running the behavior. Have the AI write the code **and tests together**, but check yourself that the tests verify something meaningful (the AI sometimes writes hollow tests that are easy to pass).
- **Static analysis** — type checking, linters, and security scanners catch defects before execution.

The key is **baking this into the pipeline.** The quality gate from Part 2, stage 4 belongs here. Block a merge when it falls below the bar, and verification becomes a system default rather than a matter of human willpower.

### Stage 3: Adversarial Verification — Have It Try to Refute

The strongest stage. The idea is simple: not **"is this right?"** but **"find why this is wrong."**

- Put the same result before **several independent verifiers** and have them *attempt to refute* it.
- Make skepticism the default — lean toward "wrong" when unsure.
- If a majority succeed in refuting, the result is discarded.

Here the **multi-agent** from Part 1 plays its part. Attach several verifiers with *different perspectives* to one result — correctness, security, "does it actually reproduce" — each a different lens. Verifiers **aimed at different failure modes** catch far more than throwing the same question N times.

> Scale verification intensity to risk. A trivial fix is fine with a read; code like payments, auth, or data migration deserves adversarial verification.

## The Trust Boundary — What to Delegate and What to Keep

However well you verify, the question remains: "can even the verification be left to AI?" The answer is to **draw the trust boundary explicitly.**

The framework is two axes.

| | Easy to reverse | Hard to reverse |
|---|---|---|
| **Low impact** | Delegate to AI, check after | Delegate but verify before applying |
| **High impact** | Delegate + automated gate | **Human makes the final call** |

- **Reversible work** — delegate boldly. If it's wrong, you roll back.
- **Hard-to-reverse, high-impact work** (production deploys, data deletion, outbound communication, secret handling) — **the human holds it to the end.** The AI may propose, but a human pulls the trigger.

This is how Part 2, stage 5's "from author to reviewer" actually works. Becoming a reviewer isn't letting go — it's **taking on the responsibility of judging what to let through and what to block.**

## Input and Output Are One Body

Part 3 covered input (tokens · instructions) and Part 4 the output (verification · trust), but the two link into a single loop.

- **A well-defined instruction** (Part 3) leaves less room for the AI to go astray, which **lowers the verification burden.**
- **Clear verification criteria** (Part 4's starting point) are in fact the same thing as the *acceptance criteria* from Part 3.

That is, pin down "what must be satisfied to be done" sharply up front, and it becomes both the instruction and the yardstick for verification. **Defining input well and verifying output well are two sides of the same coin.**

## Wrapping Up — Closing the Four-Part Series

The four parts joined into one sentence:

> **Know what you can use (Part 1), decide what stage to mature to (Part 2), feed in only what's needed and state it sharply (Part 3), and doubt and verify what comes back (Part 4).**

The tools will keep getting smarter. Hallucinations will shrink, and verification will keep automating. But the final responsibility doesn't move.

**Using AI well is, in the end, striking one balance: create fast, but doubt to the end.** Generation to the AI, judgment to the human — the better the tools get, the further the person who holds that boundary clearly will go.
