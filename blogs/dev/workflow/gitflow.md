---
title: "GitFlow Workflow - A Practical Branching Strategy Guide"
labels: ["Git", "GitFlow", "branching strategy", "version control", "software development"]
published: true
date:
readerComments: "ALLOW"
bloggerPostId: "7712560405097850619"
---

# GitFlow Workflow - A Practical Branching Strategy Guide

## Table of Contents

- [Introduction](#introduction)
- [Branch Structure](#branch-structure)
- [Main Branches](#main-branches)
  - [master / main](#master--main)
  - [develop](#develop)
- [Supporting Branches](#supporting-branches)
  - [feature](#feature)
  - [release](#release)
  - [hotfix](#hotfix)
- [Workflow in Practice](#workflow-in-practice)
- [GitFlow Commands](#gitflow-commands)
- [Tooling](#tooling)
- [Pros and Cons](#pros-and-cons)
- [FAQ](#faq)
- [References](#references)

## Introduction

GitFlow is a Git branching model proposed by Vincent Driessen in 2010. It gives a team a predictable way to develop and ship software, and it's especially effective when several developers are working in parallel on a large project.

The model lets a team work on features, release preparation, and hotfixes at the same time without stepping on each other, while keeping the production codebase stable.

## Branch Structure

A GitFlow repository has the following structure:

![GitFlow branch model](https://nvie.com/img/git-model@2x.png)

## Main Branches

GitFlow has two long-lived branches that always exist for the life of the project.

### master / main

`master` (or `main`) always reflects production-ready code.

- Every commit on this branch is tested and deployable
- Direct commits are not allowed — changes arrive only via merges from other branches
- Each release is marked with a tag so versions are easy to track

```bash
# Tag a release on master
git tag -a v1.0.0 -m "Release 1.0.0"
```

### develop

`develop` is where work for the next release lands.

- It's the starting point for all new development
- Completed features are merged in here
- When the team is ready to ship, a `release` branch is cut from `develop`

```bash
# Create the develop branch
git checkout -b develop master
```

## Supporting Branches

Three kinds of short-lived branches handle specific kinds of work.

### feature

`feature` branches are used for new features and non-urgent bug fixes.

- Branch off from `develop`
- Merge back into `develop` when the feature is done
- Naming convention: `feature/<feature-name>`

```bash
# Start a feature
git checkout -b feature/user-authentication develop

# Finish the feature
git checkout develop
git merge --no-ff feature/user-authentication
git branch -d feature/user-authentication
```

### release

`release` branches prepare a new production version.

- Branch off from `develop`
- No new features are added here — only bug fixes, documentation, and release prep
- Merge into both `master` and `develop` when ready
- Naming convention: `release/<version>`

```bash
# Start a release
git checkout -b release/1.0.0 develop

# Ship the release
# 1. Merge into master
git checkout master
git merge --no-ff release/1.0.0
git tag -a v1.0.0 -m "Release 1.0.0"

# 2. Merge back into develop so the fixes don't get lost
git checkout develop
git merge --no-ff release/1.0.0

# 3. Delete the release branch
git branch -d release/1.0.0
```

### hotfix

`hotfix` branches address urgent issues in production.

- Branch off directly from `master`
- Merge into both `master` and `develop` once the fix is in
- Naming convention: `hotfix/<version>` or `hotfix/<issue>`

```bash
# Start a hotfix
git checkout -b hotfix/1.0.1 master

# Ship the fix
# 1. Merge into master
git checkout master
git merge --no-ff hotfix/1.0.1
git tag -a v1.0.1 -m "Release 1.0.1"

# 2. Merge into develop
git checkout develop
git merge --no-ff hotfix/1.0.1

# 3. Delete the hotfix branch
git branch -d hotfix/1.0.1
```

## Workflow in Practice

A typical GitFlow cycle:

1. **Initialize the project**
   - Create `master`
   - Create `develop`

2. **Develop a feature**
   - Create a `feature` branch
   - Build and test
   - Merge into `develop`

3. **Prepare a release**
   - Create a `release` branch
   - Run QA, fix bugs found in testing
   - Merge into `master` and `develop`

4. **Handle a production incident**
   - Create a `hotfix` branch
   - Fix the issue
   - Merge into `master` and `develop`

## GitFlow Commands

The same workflow expressed as raw Git commands.

### 1. Initialize

```bash
git init

# First commit on master
git add .
git commit -m "Initial commit"

# Branch develop off master
git checkout -b develop master
```

### 2. Build a feature

```bash
# Start the feature
git checkout -b feature/login develop

# Commit work
git add .
git commit -m "Add login flow"

# Merge into develop (--no-ff preserves the branch history)
git checkout develop
git merge --no-ff feature/login
git branch -d feature/login
```

### 3. Prepare a release

```bash
# Start the release
git checkout -b release/1.0.0 develop

# Bump version, fix release blockers
git add .
git commit -m "Prepare 1.0.0 release"

# Merge into master and tag
git checkout master
git merge --no-ff release/1.0.0
git tag -a v1.0.0 -m "Release 1.0.0"

# Bring the same fixes back into develop
git checkout develop
git merge --no-ff release/1.0.0

# Clean up
git branch -d release/1.0.0
```

### 4. Ship a hotfix

```bash
# Branch off master
git checkout -b hotfix/1.0.1 master

# Commit the fix
git add .
git commit -m "Fix critical security issue"

# Merge into master and tag
git checkout master
git merge --no-ff hotfix/1.0.1
git tag -a v1.0.1 -m "Release 1.0.1"

# Merge into develop so the fix isn't lost on the next release
git checkout develop
git merge --no-ff hotfix/1.0.1

# Clean up
git branch -d hotfix/1.0.1
```

## Tooling

A few tools make GitFlow easier to apply consistently.

### Git Flow CLI

```bash
# macOS (Homebrew)
brew install git-flow

# Linux
apt-get install git-flow   # Debian/Ubuntu
yum install git-flow       # CentOS/RHEL

# Initialize
git flow init

# Feature
git flow feature start login
git flow feature finish login

# Release
git flow release start 1.0.0
git flow release finish 1.0.0

# Hotfix
git flow hotfix start 1.0.1
git flow hotfix finish 1.0.1
```

### IDE integrations

Most modern IDEs support GitFlow through plugins or built-in tooling:

- **IntelliJ IDEA / WebStorm** — Git Flow Integration plugin
- **Visual Studio Code** — GitFlow extensions
- **SourceTree** — GitFlow support is built in

## Pros and Cons

### Pros

- **Structured** — clear branching rules and a predictable workflow
- **Parallel work** — features and releases progress independently
- **Stable production** — `master` is always shippable
- **Versioning** — tags give you a clean version history

### Cons

- **Complexity** — overkill for small projects
- **Overhead** — many branches and merge points to manage
- **CI/CD friction** — modern continuous deployment pipelines sometimes find the extra ceremony unnecessary

## FAQ

### Q1. How is GitHub Flow different from GitFlow?

GitFlow is a more elaborate model with multiple branch types and stricter rules. GitHub Flow is much simpler — just `main` plus short-lived feature branches. GitHub Flow fits continuous deployment well; GitFlow fits projects with scheduled releases.

### Q2. Should small projects use GitFlow?

Usually not. For small projects or fast iteration, GitFlow adds overhead with little benefit. GitHub Flow or trunk-based development is often a better match.

### Q3. Can I add new features in a release branch?

No — by GitFlow's rules, release branches are for bug fixes and release prep only. New features belong in `develop` and should ship in the next release cycle.

### Q4. How does GitFlow combine with CI/CD?

Common setups:

- Continuous integration runs on every push to `develop`
- Release branches deploy to a staging environment for QA
- Merges to `master` deploy to production (automatically, or after manual approval)

---

GitFlow gives you a consistent, predictable release process — but it's not free. Look at your team size, deployment cadence, and how often you ship before adopting it. For large projects with scheduled releases, it's a great fit. For small teams shipping continuously, simpler models usually win.

## References

- [A successful Git branching model](https://nvie.com/posts/a-successful-git-branching-model/) — Vincent Driessen's original article
- [Atlassian — Gitflow Workflow](https://www.atlassian.com/git/tutorials/comparing-workflows/gitflow-workflow) — Atlassian's GitFlow guide
- [GitHub Flow](https://docs.github.com/en/get-started/using-github/github-flow) — the simpler alternative
