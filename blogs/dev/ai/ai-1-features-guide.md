---
title: "Using AI Well (Part 1) — What You Can Use: A Developer's Map of AI Features"
labels: ["AI", "Using AI Well", "AI agent", "LLM", "Claude Code", "developer productivity"]
published: false
date:
readerComments: "ALLOW"
bloggerPostId:
---

## Introduction

These days it's harder to find a developer who *doesn't* use AI. The options have multiplied too — ChatGPT, Gemini, Claude, and more. (As an aside: across the several models I've used, **Claude has been the best fit for me when coding.** Purely a subjective opinion.)

But ask someone "what can you actually do with AI?" and the answer often stops at "isn't it just a chatbot?" In reality, beyond the raw capability of the model, there are quite a few features that can reshape your development workflow.

This is **Part 1 of the four-part "Using AI Well" series.** The order goes like this:

- **Part 1 (this post)** — *What* you can use: a map of the features and tools AI offers
- **Part 2** — *How* to use them well: seven maturity stages for using those tools in practice
- **Part 3** — *Feeding AI well*: saving tokens (cost) and giving sharp instructions (definition)
- **Part 4** — *Trusting what comes back*: verification and trust

You can't use tools well if you don't know them, but knowing them alone doesn't make you good either. So Part 1 first lays out the **tools you can pick up**, Part 2 moves to **how to handle them**, Part 3 narrows to **what and how to feed in**, and the final Part 4 to **how to trust what comes back**.

In this post I'll lay out AI's development features in the order **models → core features → agents → multi-agent → skills → plugins**. The concepts apply to most LLMs, but I'll draw concrete examples from Claude, which I use most.

## 1. The Model Lineup — Opus, Sonnet, Haiku

Most AI providers don't offer a single model but a family split by purpose. Claude, for example, splits into three branches with names borrowed from the arts.

| Model | Character | Good for |
|------|------|--------------|
| **Opus** | Smartest; slow and expensive | Complex design, hard debugging, long reasoning |
| **Sonnet** | Balanced | Everyday coding, reviews, most real work |
| **Haiku** | Fastest and cheapest | Simple classification, bulk processing, fast responses |

Whichever model you use, the instinct is the same. The key is that **you don't always need the most expensive model.** A light, cheap model is plenty for simple repetitive work, and you pull out the smartest one only when you genuinely need to think hard — balancing cost and performance is the real-world skill.

## 2. Core Features Worth Knowing

Just calling a model works on its own, but knowing the features below changes cost and quality dramatically.

### Long Context

Today's models can process very long inputs in a single pass. That means you can drop in many files of a codebase, long logs, or dozens of pages of documents and ask questions all at once. The strength is being able to ask "where is this function used?" at the project level, not file by file.

### Prompt Caching

When you repeatedly send the same content (e.g., a long system prompt, the same codebase context), this feature caches that portion and reuses it. On a cache hit, **cost and response time drop sharply.** If your pattern is asking many questions against the same document, it's practically essential.

### Extended Thinking

Instead of answering immediately, this mode lets the model "think" enough first, then answer. Accuracy rises on hard algorithm problems or tasks needing multi-step reasoning. It uses more tokens, so it's best left off for simple questions.

### Tool Use

This makes the AI not just emit text but **directly call functions we define.** Calling a weather API, querying a DB, reading a file — it's the starting point for connecting to the outside world. This feature is the very foundation of the "agents" coming up next.

## 3. Agents — AI That Uses Tools on Its Own

When Tool Use develops further, it becomes an **agent.** Rather than answering once and stopping, give it a goal and it will:

1. Assess the situation
2. Pick and use the tools it needs (reading files, searching, running commands, etc.)
3. Look at the result and decide the next action
4. Repeat until the goal is met

A representative example is **Claude Code.** It's a coding agent that runs in the terminal — say "fix this bug" and it finds and reads files itself, edits them, and even runs the tests. You don't have to open and show it each file.

## 4. Multi-Agent — Many Agents at Once

Big jobs that one agent can't handle can be solved with multi-agent, **running several agents in parallel.**

The principle is simple. One agent breaks the work into small pieces and hands them to several subagents, and each works independently while the results are gathered and synthesized. It's like a single lead distributing work to several team members.

Tasks that fit well include:

- **Large-scale code review** — split by perspective (security, performance, bugs) and review in parallel
- **Large migrations** — split file by file, convert in parallel, then verify
- **Research** — investigate many sources at once and cross-check

### But It Isn't Free

Multi-agent is powerful, but it **consumes far more tokens.** Because each agent carries its own context and system prompt, the cost multiplies as "number of agents × each one's context."

By a figure Anthropic published, if one ordinary chat is 1, a multi-agent task can use roughly **15×** the tokens. So the key is **using it only where parallelism truly pays off.**

| Multi-agent fits | Actually wasteful |
|----------------------|------------|
| Work that must be swept broadly | Simple fact lookups |
| Scale too big for one context | Editing one or two files |
| Cross-checking from many angles | Sequentially dependent work |

The best value comes from a **hybrid**: first scope things out inline, then unleash agents only on the stretch where parallelism genuinely pays.

## 5. Skills — Packaging Repeated Work

If everything so far was "what AI can do," from here it's the realm of **"taming it to your own way."**

A **Skill** bundles a frequently used procedure into a single folder. Put in a guide (instructions) and, if needed, scripts and example files, and in similar situations the AI follows that procedure as-is. No more rewriting a long prompt every time.

The structure is surprisingly simple.

- **`SKILL.md`** — a spec describing what the skill is, when to use it, and how it works
- **Attached files (optional)** — scripts, templates, reference docs used alongside it

For example, if you make a skill for "publish a draft markdown to the blog and tidy it up in git," then "publish this post" alone runs labeling → upload → file move → commit in the set order.

The core value is **repeatability and consistency.** A task you used to delegate differently person by person, day by day, gets defined once and then runs at the same quality every time. Share it across a team and you can version-control "how our team works" like code.

## 6. Plugins — Installing a Whole Capability at Once

If one skill is "a bundle of one procedure," a **Plugin** is a **package** that bundles several capabilities into one installable unit. Think of a browser extension or a VS Code extension.

A single plugin usually includes things like:

- **Skills** — the procedure bundles seen above
- **Subagents** — agents specialized for a particular role
- **Hooks** — actions that run automatically at certain moments (e.g., before a commit, after a task finishes)
- **MCP server connections** — integration with external tools and data sources

Instead of copying your homemade skills into a folder every time, bundle them as a plugin and put it on a **marketplace**, and others can install it with a one-line command. Think of it as the unit for distributing and sharing "settings, tools, and automation" as a whole.

> **Skill vs Plugin** — a skill is the definition of "how to do one task," while a plugin is the packaging of "how to bundle such skills and tools for distribution and sharing."

## Summary

AI's development features in one line:

> **Pick a model (Opus/Sonnet/Haiku), refine with caching/reasoning/tools, delegate work to an agent, split big jobs across multi-agent, bundle repeated work into skills, and distribute the bundle as a plugin.**

What matters isn't memorizing each feature but the **instinct for picking the right tool for the size and nature of the work.** Throwing an expensive model and multi-agent at a simple job is overkill; conversely, grinding through a huge job with a single agent is inefficient.

The better the tools get, the more the difference comes down to a person's judgment of "what to solve with which tool."

## Coming Up Next

That was "what you can use." But knowing the features doesn't immediately make you good at using them. Someone who uses AI only for autocomplete and someone who hands an entire ticket-sized task to an agent get completely different results from the same tools.

So **Part 2 covers "how to use them well."** It splits AI usage into a **seven-stage maturity ladder** — *using as a tool → delegating → automating → supervising → autonomy* — to check where your way of working sits and how to climb the next rung. The agents, multi-agent, and skills from this post naturally find their place on those stages.

Then **Part 3** digs into the two real-world problems everyone eventually hits on top of that: **"why is this costing so much?" (tokens)** and **"why won't it do what I told it?" (instructions).** And the final **Part 4** closes the series with **how to trust and verify what comes back.**
