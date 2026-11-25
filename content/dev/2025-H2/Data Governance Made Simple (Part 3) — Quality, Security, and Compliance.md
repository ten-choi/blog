---
title: "Data Governance Made Simple (Part 3) — Quality, Security, and Compliance"
labels: ["Data Platform Series","Data Governance","Data Quality","Data Security","Data Privacy","Compliance","Data Engineering","Archive"]
published: true
date: 2025-12-19T11:31:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "4291189687823124488"
source: "archive"
archivePath: "_archive/data/14-governance-3-quality-security-compliance.md"
---

**Data Platform Series · 14/15** · Data Governance 3/3

> This is the last part of the series. Parts 1 and 2 covered *what* governance is and how to *find and trace* data. This part is about the enforcement side: how to make data trustworthy, keep it safe, and stay within the law.

## 1. Data Quality: Trust You Can Measure

Everyone wants "good data," but "good" isn't a feeling — it's a set of measurable dimensions. If you can't measure a quality problem, you can't even tell whether it's getting better or worse. Here are the dimensions worth tracking:

| Dimension | The question it answers | Failure example |
|-----------|-------------------------|-----------------|
| **Accuracy** | Do the values match reality? | A customer's country is wrong |
| **Completeness** | Are required values filled in? | 12% of orders have a null `user_id` |
| **Consistency** | Do systems agree with each other? | CRM and billing totals differ |
| **Timeliness** | Is it fresh enough? | The "real-time" dashboard is 6 hours behind |
| **Uniqueness** | Are there unwanted duplicates? | The same order was counted twice |
| **Validity** | Does it follow the rules? | An email field with no `@` |

The practical approach is to turn these dimensions into **automated checks** that run alongside your pipelines — asserting that `user_id` is never null, that row counts don't drop by more than 20% from one day to the next, that freshness stays within an hour.

You write these checks in code, not in your head. In dbt, for example, you just declare tests next to the model:

```yaml
# schema.yml — orders model
columns:
  - name: user_id
    tests:
      - not_null      # fails on null
      - unique        # fails on duplicates
```

With tools like Great Expectations or Soda, you can declare expectations in YAML or SQL and even check freshness and distribution shifts. But the key isn't the tool — it's one thing: **what happens when a check fails.**

> **Real-world trap:** a check that only raises a warning and pages nobody is theater. A red dot in the corner of a dashboard that nobody looks at might as well not exist. Tie failures to real action: (1) send an alert to the owner via Slack/PagerDuty, (2) fail the test in CI to block the deploy, or (3) halt the pipeline and move bad rows into a quarantine table so only good data flows downstream. The right owner should find out *before* stakeholders notice the error.

> This connects directly to the "data contract" idea from Part 1. A quality expectation stops being a good intention the moment it becomes a check that fails loudly. A definition nobody enforces is just a comment.

---

## 2. Data Security: Who Can See What

Security in governance is mostly about **access control** — making sure each person and system can see only the data they're allowed to.

### Classification Comes First

Not all data is equal, so you can't protect it uniformly. The starting point is **classification**: tagging data by sensitivity.

- **Public** — fine to show anyone (e.g., published blog content).
- **Internal** — for employees; little harm if leaked (e.g., aggregate metrics).
- **Confidential** — restricted access; real harm if leaked (e.g., per-customer revenue).
- **Restricted / PII** — personal or regulated data with legal consequences (e.g., names, emails, payment details).

Once data is classified, rules can be applied automatically by following the tags, instead of deciding every case individually.

### Controlling Access

The most common model is **role-based access control (RBAC)**. Permissions are granted to *roles* (analyst, engineer, support), and people are assigned those roles. This scales far better than granting individuals access one table at a time — when someone changes teams, you change their role instead of touching 50 grants.

In practice, RBAC ends up as GRANT statements inside the warehouse. The key is to give permissions to *roles* and assign people to *roles*. Never grant directly to individuals, table by table.

```sql
-- Same pattern in Snowflake and BigQuery
GRANT SELECT ON analytics.orders TO ROLE analyst;  -- permissions go to the role
GRANT ROLE analyst TO USER jane;                    -- people get assigned to the role
```

If you need finer-grained control, there's **attribute-based access control (ABAC)**, where access is decided by attributes of the user, the data, and the context (e.g., "support agents can see customer data, but only for customers in their own region"). It's more powerful but more complex, so reach for it when roles alone can't express the rule.

### Masking and Anonymization

Sometimes you need to work with a dataset without seeing its sensitive parts. There are two techniques:

- **Masking** — hiding part of a value while keeping it usable: `j•••@example.com`, or showing a credit card as `**** **** **** 4321`. The structure stays; the secret goes.
- **Anonymization / pseudonymization** — removing or replacing identifiers so a record can't be traced back to a specific person. *Anonymization* aims to make re-identification impossible; *pseudonymization* replaces identifiers with tokens that can only be reversed with a separately stored key.

Modern warehouses support this through **dynamic data masking**: a policy that leaves the original intact but makes the same column look different depending on *who is querying*. When the analyst role runs `SELECT email FROM users`, it gets masked values back, like this:

```text
email
-----------------
j•••@example.com   -- what the analyst sees
jane@example.com   -- the support role sees the original
```

These techniques let analysts and ML teams work with realistic data without ever touching the raw personal information.

> **Real-world trap:** don't fool yourself into thinking pseudonymized data is "no longer personal data." As long as a key to reverse it exists somewhere, GDPR and many other laws still treat pseudonymized data as personal data. Masking hides the screen, not your legal liability.

---

## 3. Compliance: The Rules You Can't Opt Out Of

Privacy regulation is where governance turns from best practice into legal obligation. The specific laws vary by region — the EU's **GDPR**, California's **CCPA/CPRA**, and equivalent laws in many countries — but they share a common spine that engineers should understand.

**① Know what personal data you hold, and why.** "We collect some user data" is an indefensible position. You need an inventory of what personal data you have, where it lives, and the legitimate purpose for holding it. (This is where the catalog and classification covered earlier pay off directly.)

**② Purpose limitation.** You can't freely reuse data collected for one reason for something else. An email collected for order confirmations doesn't automatically become yours to feed into an ad model.

**③ Individual rights.** People can ask what you hold about them, ask you to correct it, and — the one that weighs most heavily on engineering — ask you to **delete** it. The "right to be forgotten" means you have to be able to *find and remove* one person's data across every system.

When a deletion request actually comes in, the runbook goes roughly like this:

1. **Find** — use lineage (Part 2) and PII tags to pin down *which systems and which tables* that person's data is scattered across. Without this step, everything after it is guesswork.
2. **Delete** — remove the relevant rows from each system. This is where the lakehouse's **row-level delete** shines: work that used to mean rewriting an entire huge Parquet file can now be done by marking just that one person's rows as deleted.
3. **Record** — write to an audit log *whose data was deleted, when, and under which request*. You need to be able to prove that the deletion happened.

The key is to **classify and tag** PII up front. Then the rules above apply automatically *by following the tags* rather than column by column, so nobody has to babysit each new table as it appears.

**④ Retention limits.** You're required to keep personal data only as long as you actually need it, and dispose of it afterwards. Storing it indefinitely "just in case" is a liability, not an asset.

**⑤ Auditability.** You have to be able to show *who* accessed *what*, and *when*. Access logs and audit trails turn "we take privacy seriously" into something you can actually prove.

> **Real-world trap:** the most common failure is "policy without enforcement." If the retention policy is written in the wiki but nobody actually runs a job that deletes expired data, or there's a documented procedure for deletion requests but the team fumbles through it by hand when one arrives — that policy is just paper in an audit. A policy is real only when it's enforced by code and a scheduler.

> None of this requires you to become a lawyer. It just requires the data platform to be designed so these questions have answers. And that's exactly what governance is about.

---

## 4. Governance in the Age of AI

One last note, because it's where the field is heading. When data feeds machine learning, every governance concern gets sharper.

- **Quality** matters more, because one bad column doesn't stop at one report — it degrades a model, quietly and at scale.
- **Lineage** has to extend to models. *Which* data trained *which* model becomes a question you have to answer — and sometimes regulators are the ones asking.
- **Privacy** gets subtle. Models can memorize and leak training data, so "we anonymized the table" isn't automatically the end of the story.

The teams that invested in governance early are the ones that can adopt AI *safely* now. The ones that didn't are learning that trust isn't something you can bolt on after the platform is built.

---

## 5. Wrapping Up the Series

Three parts, one consistent thread:

- **Part 1** — Governance is people, policies, and processes: clear ownership and shared definitions, not a product.
- **Part 2** — Metadata, catalogs, and lineage make data findable and traceable.
- **Part 3** — Quality, security, and compliance make data trustworthy, safe, and lawful.

Data governance has a reputation for being dull, but the goal behind it is anything but bureaucratic: a data platform people actually *trust*, and keep trusting as data, regulations, and use cases grow. Start small. Name an owner. Define one term. Add one quality check. Governance is built one honest answer at a time.
