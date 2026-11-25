---
title: "Business Intelligence — Turning Data Into Decisions"
labels: ["Data Platform Series","Business Intelligence","BI","Analytics","Data Visualization","Dashboards","Data Engineering","Archive"]
published: true
date: 2025-12-25T18:28:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "4419259817790932921"
source: "archive"
archivePath: "_archive/data/15-bi.md"
---

**Data Platform Series · 15/15** · Using the Data (Finale)

> Everything else in this curriculum — pipelines, warehouses, lakes, governance — ultimately exists for this final step: getting people to actually *use* data to make decisions. That's business intelligence. This post explains what BI is, what kinds of questions it answers, and why BI can only ever be as good as everything underneath it.

## 1. The Real Purpose of the Platform

Let's step back and remember why all of this exists. We collect data, build pipelines, model warehouses, and manage quality. But none of it means anything unless someone, somewhere, makes a *better decision* because of that data. **Business intelligence (BI)** is the layer where that finally happens.

> **Business intelligence is the set of tools and practices for analyzing data and presenting it so people can make informed business decisions.**

If the rest of the platform is the kitchen, BI is the food that comes out of it. The dashboard executives check every morning, the report a manager pulls up before a meeting, the chart that reveals one region's sales are slipping — that's all BI. BI turns rows in a database into answers people can act on.

In practice, the tools for this layer are fairly settled. On the commercial side, Looker, Tableau, and Power BI are common; on the OSS side, Metabase and Superset get used a lot. The tools differ, but what they do — build dashboards, open up self-service exploration, deliver reports on a schedule — is nearly the same.

---

## 2. The Questions BI Answers

One useful way to understand BI is to look at the *kinds of questions* it handles. They climb a ladder of increasing sophistication:

| Type | Question | Example |
|------|----------|---------|
| **Descriptive** | What happened? | "Revenue fell 8% last month." |
| **Diagnostic** | Why did it happen? | "Because returns spiked in the EU." |
| **Predictive** | What will happen? | "Revenue will likely fall further next month." |
| **Prescriptive** | What should we do? | "Fix the size guide to reduce returns." |

Traditional BI mostly lives on the bottom two rungs — **descriptive and diagnostic** — answering *what happened* and *why*. The top two rungs (predictive, prescriptive) cross into data science and machine learning, which consume the same underlying data. The line between "BI" and "advanced analytics" is blurry and getting blurrier. But the foundation is always the same: understand the past clearly before you try to predict the future.

---

## 3. What BI Actually Looks Like

BI shows up in a few recurring forms:

- **Dashboards** — collections of live charts and key metrics that refresh automatically. The screen the CEO glances at in the morning, the wall display in the operations room.
- **Reports** — structured, often recurring documents ("monthly sales report"), sometimes delivered automatically on a schedule.
- **Self-service exploration** — tools that let non-technical users slice and filter data themselves, building the views they want without writing SQL or waiting on the data team.
- **Ad-hoc analysis** — analysts digging deeper into a specific question with one-off queries.

The biggest shift over the years has been the move toward **self-service**. Instead of every question going through the data team, modern BI tools let business users answer questions themselves within defined guardrails. That massively scales how an organization uses data — *but only* if the data underneath is trustworthy and well defined.

> **Real-world trap — dashboard sprawl.** Open up self-service and anyone can build a dashboard, and you end up with seven dashboards titled "Monthly Revenue" floating around and nobody knows which one is right. Two people showing up to a meeting with different numbers and arguing over them is a familiar scene in any data organization. The fix isn't locking down the tool — it's **governance**: the semantic layer and certification covered in the next sections.

---

## 4. The Semantic Layer: How to End "Five Different Numbers"

The most painful problem self-service unleashes is that different people calculate the same metric differently. Someone defines "active user" as a login within 30 days; someone else as a transaction within 7 days. Whether revenue subtracts refunds varies from person to person. The result is exactly "the same metric, five different numbers across dashboards."

The practical mechanism that ends this structurally is the **semantic layer**, also called the **metrics layer**. The core idea is simple: define each metric *once, in one place*, and have every dashboard use that same definition. Looker's LookML and dbt metrics are typical implementations.

In LookML, for example, the revenue metric is declared once like this:

```lookml
measure: revenue {
  type: sum
  sql: ${order_amount} - ${refund_amount} ;;
  value_format_name: usd
}
```

Now whichever dashboard pulls in `revenue` gets the same calculation with refunds subtracted. Because the definition is pinned in code in one place, changing it means changing the code and going through review — and the change is reflected in every chart at once. The metric becomes **a single, version-controlled asset** instead of scattered SQL fragments.

---

## 5. The OLAP Idea: Slicing and Dicing

BI tools are built around an interaction style with a name worth knowing: **OLAP** (online analytical processing), the analytical counterpart to the OLTP/operational databases covered in Part 1 of the warehouse posts.

The core of OLAP is looking at a measure across multiple **dimensions** and flexibly rearranging that view. If the terms sound familiar, that's no accident — they're exactly the **facts and dimensions** of the dimensional modeling we covered. Here are a few standard OLAP operations:

- **Slice** (as in **slice and dice**) — fix one dimension ("EU region only").
- **Dice** — filter on several dimensions at once ("EU, last quarter, electronics").
- **Drill down** — go from summary to detail ("year → quarter → month → day").
- **Roll up** — aggregate back up ("daily → monthly totals").

This is exactly why the modeling work mattered. A well-built star schema is what makes a BI tool's slice-and-dice feel instant. **Good BI lives downstream of good modeling.**

---

## 6. Visualization: Showing Data So People Understand It

A core part of BI is presenting data *visually*, because charts convey patterns far faster than a table packed with numbers. It's a small craft in its own right, with a few principles that separate clarity from clutter:

- **Match the chart to the question.** Trend over time → line chart. Comparison across categories → bar chart. Part of a whole → use sparingly (pie charts are easy to misread). Picking the wrong chart buries the very insight you meant to show.
- **Simpler is better.** Strip out decoration that carries no information. The thing shouting loudest on the screen should be the data.
- **Don't mislead.** Truncated axes, distorted scales, and cherry-picked ranges can make a chart technically accurate yet deeply misleading. BI carries a quiet ethical responsibility: show data so people reach the *right* conclusion, not the one you wanted them to reach.

> **Real-world trap — distorted axes and the wrong chart.** Start the y-axis somewhere other than zero and a 2% change looks like a cliff. Even if it's an honest mistake, viewers read it as "we're in trouble." Cramming seven categories into a pie chart likewise makes comparison hard. Just checking two things at review time — "does this axis start at zero?" and "is this the right kind of chart for this question?" — prevents most misreadings.

> A chart isn't decoration; it's an argument. Good data visualization makes the true story obvious, and bad visualization (deliberately or by mistake) makes a false story look obvious.

---

## 7. Governed Self-Service: Letting People Explore Safely

The practical answer to reconciling self-service freedom with trust is **governed self-service**: business users explore freely, but within fences that keep them from re-deriving metrics every time. In practice this shows up as a few concrete mechanisms:

- **Certified/verified dashboards** — dashboards validated by the data team get a certification badge. Tableau's Certified, Power BI's endorsed/certified, and Looker's curated folders are examples. Users don't have to wander around wondering "which one is right" — they just trust the certified one.
- **Curated metrics catalog** — a menu where users search for and pull in metrics defined in the semantic layer from section 4. Instead of writing SQL themselves, they combine validated metrics.
- **Guardrails** — row-level security restricts what data users can see, and some fields are exposed only through certified metrics.

The key is that it's not a binary choice between "lock it down" and "open it up." Put trustworthy metrics at the center and allow freedom to explore around them — that's how you prevent dashboard sprawl while keeping the speed of self-service.

---

## 8. How to Debug "The Dashboard Is Wrong"

When the business side reaches out with "the numbers on this dashboard look weird," a practitioner's instinct is to suspect the BI tool — but it's almost never a BI bug. The problem is somewhere upstream, and the tool for tracing it is **lineage**. Just walk the same lineage covered in Governance Part 2 backwards.

The practical tracing order goes roughly like this:

1. **Start with the metric definition** — check how this metric is calculated in the semantic layer. Surprisingly often, the definition itself differs from what people expect.
2. **Trace upstream with lineage** — follow which model/table this chart comes from. A join in the modeling step may have created duplicate rows, or two sources may have diverged at the integration step.
3. **Check ingestion and freshness** — look at when the last load happened. "Yesterday's data is missing" isn't a dashboard bug; it's a pipeline delay.

Following lineage this way quickly shows that "BI is wrong" really means "something upstream was wrong, and it finally surfaced where people could see it."

---

## 9. BI Is Only as Good as What's Underneath

Here's the lesson that ties BI back to this entire curriculum, and the one most worth remembering. A BI dashboard is the *visible* top of a deep stack, and it inherits every weakness underneath it.

- If **data ingestion** missed data → the dashboard is incomplete.
- If **integration** failed → two charts disagree and trust evaporates.
- If **modeling** is wrong → the metric means something other than what people think.
- If there's no **governance** → nobody knows whether to trust the number, or even what it means.

That's why "the dashboard is wrong" is almost never truly a BI problem. It's a problem somewhere upstream that finally surfaced where everyone could see it. BI is the layer where all of the platform's hidden flaws become *visible* to the business. And that's exactly why every layer beneath it — pipelines, storage, governance — matters: they're what make BI trustworthy.

The flip side of this is the reward. When the whole stack is solid, BI is where all that effort pays off — the point where a clean, well-governed, well-modeled platform turns into people across the company making faster, better-informed decisions every day.

> **BI reliability checklist**
> - Are core metrics defined *once* in a semantic layer (LookML, dbt metrics, etc.)?
> - Do the dashboards the business looks at carry a certified/verified mark?
> - Do chart axes start at zero, and does the chart type fit the question?
> - When a "this is wrong" report comes in, can you trace it upstream with lineage?
> - Is there a regular cycle for cleaning up and certifying sprawling dashboards?

---

## 10. Key Takeaways

Business intelligence is the consumption layer where data finally turns into decisions — through dashboards, reports, and self-service exploration that answer *what happened* and *why*. It's built on OLAP's "slice and dice" model (and therefore on good dimensional modeling), ends "five different numbers" by defining metrics once in a semantic layer, lives or dies by clear visualization, and above all, **can only be as trustworthy as the pipelines, storage, and governance underneath it.**

And that closes the loop on the Data Platform series. We started with a map of how the pieces fit together, dug into storage (warehouses, lakes, lakehouses, marts), followed how data moves (pipelines, ingestion, ETL/ELT, integration, modeling, streaming), governed it for trust (the Data Governance series), and have now arrived at the destination of it all: turning that data into decisions.
