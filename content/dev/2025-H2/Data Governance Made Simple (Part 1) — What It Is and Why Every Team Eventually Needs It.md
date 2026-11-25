---
title: "Data Governance Made Simple (Part 1) — What It Is and Why Every Team Eventually Needs It"
labels: ["Data Platform Series","Data Governance","Data Management","Data Quality","Metadata","Data Engineering","Archive"]
published: true
date: 2025-12-07T16:54:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "6280740213053691774"
source: "archive"
archivePath: "_archive/data/12-governance-1-foundations.md"
---

**Data Platform Series · 12/15** · Data Governance 1/3

> A practical primer on data governance for engineers who keep hearing the term in meetings but have never had anyone properly explain what it means.

## 1. The Problem Nobody Owns

Picture a company about three years into its growth. There are five dashboards reporting "monthly active users," and every one of them shows a different number. Marketing trusts its own dashboard, the data team trusts the fourth one, and nobody can explain the difference — because nobody remembers how each one was built.

This isn't a tooling problem. The warehouse is fine, the BI tool is fine, and the pipelines run just fine. The real problem is that **nobody owns the definition of "active user,"** nobody knows where the number comes from, and nobody is accountable when the numbers drift.

That gap — the absence of clear ownership, shared definitions, and trust in the data — is exactly what data governance exists to fill.

---

## 2. So What Is Data Governance?

Here's the short definition:

> **Data governance is the set of people, policies, and processes that decide how an organization's data is defined, produced, protected, and used.**

Notice what's *not* in that sentence: a product. Governance isn't a tool you install. It's a set of agreements about your data, and tools merely support it. The tools (catalogs, quality monitors, access control systems) come later, and they only help if the agreements exist first.

To understand governance, it helps to break it down into a few questions a healthy data organization should be able to answer quickly:

| Question | Governance area |
|------|---------------|
| What does this data *mean*, and who decides that? | Definitions / business glossary |
| Where did this number come from? | Lineage / metadata |
| Can we trust this data today? | Data quality |
| Who is allowed to see this? | Security and access control |
| Are we even allowed to keep this? | Privacy and compliance |
| Who do we ask when something goes wrong? | Ownership / stewardship |

If your team struggles to answer any one of these, that's a governance gap — not the personal fault of whoever happened to get asked.

---

## 3. Why It Suddenly Matters More Than It Used To

Data governance has existed in large enterprises for decades, but it was once a concern mainly for banks and insurers. Three shifts have made it everyone's problem.

**① The volume and variety of data exploded.** A single company today produces event logs, transactional databases, third-party APIs, and unstructured text. When your data was one tidy SQL database, you could keep the rules in your head. Not anymore.

**② Regulation grew teeth.** Privacy laws (GDPR, CCPA, and countless regional cousins) turned "we store some user data" into a matter with legal and financial consequences. You now have to *know* what personal data you hold and be able to prove how you handle it.

**③ AI and ML raised the stakes on quality.** One bad row in a report misleads one analyst. But one bad column feeding a model can quietly break a product used by millions. The moment companies started training on their own data, "garbage in, garbage out" became a board-level risk.

---

## 4. The People Side: Who Actually Does This Work

The most common reason governance fails isn't that the policies are wrong — it's that **nobody has been named as responsible**. A handful of standard roles solve this. Titles vary from company to company, but the responsibilities are remarkably consistent.

- **Data owner** — usually a business leader (e.g., the head of marketing for marketing data). Accountable for *what the data means* and who may use it. Sets policy, but doesn't write SQL.
- **Data steward** — the hands-on caretaker of a specific domain. Maintains definitions, keeps an eye on quality, and answers "what does this column mean?" It's the most important governance role, and also the one most often missing.
- **Data custodian** — usually the engineering/platform team. Responsible for the *technical* care of the data: storage, pipelines, backups, enforcing access control.
- **Data consumer** — analysts, scientists, app developers. They're not passive; they're expected to report problems and use the data within policy.

In practice, these roles are filled not by hiring new people but by **attaching responsibilities to people you already have**. Take payments data: the owner is the PM or team lead for the payments domain, the steward is the analyst/engineer who looks at that domain every day, the custodian is the platform team, and the consumers are every team that uses the data. One person often wears several hats, but *being named* is the whole point.

The key idea: **ownership is assigned, not assumed.** "The data team owns the data" is a non-answer. The data team can run the pipelines, but it can't decide what "active user" means for the business — that's the domain's job. So ownership has to be named per domain. Owning *every* domain amounts to owning nothing.

---

## 5. A Mental Model: Governance as a Contract

If you take away just one thing from this post, take this framing: every important dataset should come with an implicit contract.

- **Definition** — what each field means in business terms.
- **Origin** — where it comes from and how it's produced.
- **Quality expectations** — what "good" looks like (no nulls in `user_id`, freshness within 1 hour, etc.).
- **Access rules** — who can read it, and under what conditions.
- **Owner** — one person's name, not a team.

If this "contract" sounds abstract, in practice you write it down as a single file. Not some grand standard — just a short document the team keeps in version control alongside the code.

```yaml
dataset: daily_active_users
owner: jane.kim          # a person's name, not a team
fields:
  user_id: "Unique user identifier (not PII)"
  active_date: "Date the user opened at least one session (UTC)"
freshness_sla: 1h        # refreshed hourly, alert on delay
quality:
  - user_id not null
  - active_date >= '2020-01-01'
```

The nice thing about keeping it as a file is that definition changes get reviewed in a PR, and there's a record of who changed what, when, and why. When all five of these are documented and someone is accountable for them, you have governance. If they live only in the head of whoever built the pipeline two years ago, you have a risk.

---

## 6. Start Like This: The First Three Steps

Governance carries a reputation for being "bureaucratic," and that reputation usually comes from doing things in the wrong order — writing a pile of policy documents first, or buying an expensive catalog tool first. **Agreements come before tools.** Start small, with the one place that hurts most.

1. **Name an owner for your single most troublesome metric.** Pick the metric whose numbers never match in meetings (e.g., "active user") and attach the name of *one person* who is accountable for its definition.
2. **Write that definition down once, in one place.** A shared wiki or a Google Sheet is enough at first. What matters isn't the tool but the fact that "the definition lives in exactly one place." Catalog tools like DataHub or OpenMetadata can come in once definitions start multiplying and scattering (covered in Part 2).
3. **Put one quality check on that data.** For example, a single check that `user_id` is never null. If you use dbt, make it a dbt test; otherwise you can start with a tool like Great Expectations, or even a simple query.

With just these three — one owner, one line of definition, one check — governance has already started. From there, you add domains one at a time.

**Common pitfalls in practice:**

- **Governance with documents but no one responsible.** Rules and policy documents pile up, but when someone says "this metric is wrong," there's nobody designated to fix it. The owner's name comes before the documentation.
- **Buying tools before reaching agreement.** It's easy to assume adopting a catalog tool gives you governance. Without definitions and owners to fill it, all you get is an expensive, empty catalog.
- **Trying to own everything at once.** Trying to govern all of the company's data at once leaves you exhausted and accomplishing nothing. You're better off taking one painful domain all the way through.

---

## 7. What This Series Will Cover

This post covered the vocabulary, the *why*, and the first steps. The rest of the Data Governance series gets more concrete.

- **Part 2 — Metadata, the data catalog, and lineage.** How organizations make data *findable* and *traceable*. We'll talk about the difference between technical and business metadata, what a data catalog actually does, and lineage — the feature everyone wished they'd had during the last incident.
- **Part 3 — Data quality, security, and compliance.** The dimensions used to measure quality, how access control and data masking work in practice, and what privacy regulations demand of engineering teams.

Governance carries a reputation for bureaucracy. But it doesn't have to. Done well, governance is simply the difference between a data platform people trust and one they quietly route around.
