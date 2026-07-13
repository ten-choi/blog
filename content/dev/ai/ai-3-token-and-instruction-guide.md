---
title: "Using AI Well (Part 3) — Save Tokens and Instruct Properly"
labels: ["AI", "Using AI Well", "tokens", "context", "prompting", "developer productivity"]
published: true
date:
readerComments: "ALLOW"
bloggerPostId: "5637210750479059666"
---

## Introduction

This is **Part 3 of the four-part "Using AI Well" series.**

- **Part 1** — *What* you can use: a map of models, features, agents, skills, plugins
- **Part 2** — *How* to use it well: seven maturity stages
- **Part 3 (this post)** — *Feeding AI well*: **tokens (cost)** and **instructions (definition)**
- **Part 4** — *Trusting what comes back*: verification and trust

If the first two parts were "the big picture," this post tackles two very concrete problems you hit every day in the field: **"why is this costing so much?" (tokens)** and **"why won't it do what I told it?" (instructions).**

For each problem I've brought one real-world example. Neither is a pitch to use a specific tool — they're examples for borrowing **the idea inside them.**

- **LLMLingua** — Microsoft's open-source tool that compresses the prompt before sending it, to save tokens
- **Elicitation** — the technique of having the AI question you back to define the task clearly (standardized example: MCP Elicitation)

## Tokens — "Why Is This Costing So Much"

### Where Do Tokens Leak

Agents eat more tokens than you'd think. And most of it goes not to "smart reasoning" but to **hauling junk around.**

- Tool output — verbose JSON, hundreds of lines of logs
- Retrieved document chunks (RAG) — pulled in whole when only part is used
- Accumulating conversation history — heavier with every turn

As we saw in Part 1, multi-agent **multiplies this by the number of agents**, so cost explodes. In the end the key to saving tokens is simple: **send the model only what it actually needs.**

### Example: LLMLingua — "Compress Before Sending"

A representative example is **LLMLingua**, open-sourced by Microsoft. At the stage **before** input reaches the model, it uses a small language model to filter out low-information tokens and compress the prompt. By the papers, it achieves **up to 20× compression with only a small performance drop**, and the long-context/RAG follow-up LongLLMLingua reported a **~94% cost reduction** on one benchmark. (The numbers vary by task and data, and "a small drop" means exactly that — not "none at all.")

The idea to borrow is simple: **keep only the information the model actually uses, and trim the rest.**

### Principles You Can Apply Without Any Tool

Even without a tool like LLMLingua, you can apply the same thinking by hand.

1. **Don't throw raw material in as-is** — summarize long logs/files first, or cut to the relevant part before inserting.
2. **Reuse the cacheable parts** — put repeated system prompts and code context through prompt caching (see Part 1).
3. **Trim the conversation history** — replace the long record of finished work with a summary to keep the context light.

> In one line: **the surest way to save tokens is not to send them.**

## Instructions — "Why Won't It Do What I Told It"

### The Problem Isn't the Model, It's the Definition

When AI produces something off-base, the cause is usually not that the model is dumb but that **the instruction was vague.** Say "just do it nicely" and the AI fills the blanks **with its own assumptions.**

In Part 2, stage 3, we said the quality of delegation comes down to **structuring the input.** Instructing well ultimately means making four things sharp: **input, output, constraints, and acceptance criteria.**

The problem is that people usually **can't write all this perfectly up front.**

### Two Roads to a Clear Definition

So how do you actually reach a sharp definition? There are two roads, and they aren't rivals.

- **(A) Write a PRD/spec first.** Agree on the goal, scope, and acceptance criteria in a document before any code, then delegate with "implement this per the PRD." This fits big tasks, work involving several people, and hard-to-reverse changes. A written spec also doubles as the yardstick for verification later (see Part 4).
- **(B) Elicitation — let the AI ask.** Starting from near-blank, the AI questions you and you unearth the definition together. This fits exploratory or smaller work, where writing a full spec up front would be wasted effort.

In practice the strongest move is to **combine them**: draft a rough PRD, then hand it to the AI with "before you start, grill me on anything missing or ambiguous in this PRD." The document gives structure; the questioning fills its holes.

Road (A) is straightforward — you already know how to write a spec. Road (B) is the one worth seeing in action.

### Example: Elicitation — "Instead of Me Writing It, the AI Questions Me"

The idea is satisfyingly backwards. Rather than straining to write a perfect spec, you make the **AI interrogate you like an interviewer.** This "asking back" pattern is becoming standardized, too. The open standard **MCP (Model Context Protocol)**, led by Anthropic, specifies an **Elicitation** feature in which the AI requests needed information from the user mid-task, and frameworks like Spring AI provide similar "ask the user a question" tools.

Good asking-back shares some traits:

1. Ask **one question at a time** (sequentially, not a barrage)
2. Walk the **dependencies between choices (a decision tree)** as it asks
3. If the answer can be found in the codebase, **dig it up directly** to confirm
4. Offer a **recommended answer alongside** each question
5. Continue **until both sides' understanding lines up**

In other words, it treats the task's definition not as something "written out fully in advance" but as something **"unearthed together through conversation."** People only realize what they left out once they're asked.

### Principles You Can Apply Without Any Tool

- Before throwing a task over, ask the AI to **"question me about anything ambiguous before you start."**
- The bigger the decision, the more you **confirm one at a time** and build agreement.
- Have the AI **explicitly restate** its assumptions so misunderstandings get caught early.

> In one line: **if you lack the ability to instruct well, you can substitute making it ask well.**

## Where the Two Axes Meet

Tokens and instructions look like separate problems, but they're really one body.

| Axis | What it covers | When it goes wrong |
|----|----------|---------|
| **Tokens** | Cost · speed | Money leaks, things slow down |
| **Instructions** | Quality · accuracy | Wrong results, rework |

The link is **rework.** When a vague instruction sends the AI down the wrong path, fixing it drags the conversation out → **more tokens leak.** Conversely, define it well and hit it in one go, and you get both better quality and saved tokens.

So **"instructing properly" is not just a quality strategy but a cost-saving one too.**

## Wrapping Up

Part 3's core is, in the end, **input.**

> **Send only what's needed (tokens), and make clear what you want (instructions).**

The tools keep getting better. Context compression and features that ask questions for you will grow smarter. But the principle underneath doesn't change. This is how you **feed** AI well.

But feeding it well isn't the end. **Whether what comes back is actually right** is a separate problem. The final Part 4 covers that output side — how to doubt and verify an AI that's confidently wrong — closing the series with **verification and trust.**
