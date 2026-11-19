---
title: "Mermaid vs Archify - Choosing the Right Tool for Architecture Diagrams"
labels: ["Mermaid","Archify","architecture diagram","documentation","software development"]
published: true
date: 2026-05-15T10:00:00+09:00
readerComments: "ALLOW"
bloggerPostId: "3667831273068738507"
source: "archive"
archivePath: "_archive/dev/workflow/mermaid-vs-archify-architecture-diagrams.md"
---

## Introduction

Our team wiki has an overview page that maps the whole system. It is drawn in Mermaid, and for a long time that was fine. Then the system grew to around 43 domains, and the page quietly stopped being useful. The auto-layout squeezed everything together, the arrows crossed each other, and there was almost nothing you could do about it by hand.

That is the moment most teams discover that "diagram as code" tools are not all the same. Mermaid and Archify both let you describe a diagram in text and render it, but they sit at opposite ends of a trade-off: **how much you control the picture versus how easily the picture goes into a document.** This post lays out the difference and when each one makes sense.

## Mermaid: write the structure, let the renderer draw it

Mermaid takes a small text grammar, something like `graph LR` followed by `A --> B`, and the renderer works out the layout for you. You never specify a coordinate.

That single design choice explains most of its strengths and weaknesses.

- **It goes anywhere.** Notion, GitHub, GitLab, Confluence and most other wikis render Mermaid natively. Put it in a Notion code block with the language set to `mermaid` and the diagram appears inline on the page. There is no build step and no file to host.
- **It is fast to write.** A dozen nodes and their edges take a minute. For a pull request description or a design note, that speed matters more than polish.
- **The output is a static SVG.** No clicking, no focus, no switching views. What you see is all there is.
- **Layout is out of your hands.** When the node count grows, the automatic placement collapses. Edges tangle, labels overlap, and there is very little room to fix it manually. The 43-domain overview page is exactly this failure.

Mermaid is optimized for the common case: a small diagram that lives inside a document and is read once.

## Archify: specify the picture, and have it checked

Archify goes the other way. Its input is a JSON spec that states node coordinates, bounding boxes, edge routes (`via` points), and label positions explicitly. On top of that sits a validator that treats layout problems as errors: an edge passing through a node, two labels overlapping, and similar rule violations fail the build instead of silently rendering badly.

The consequence is that building the diagram takes noticeably more effort, but the result comes out the way you intended, every time.

- **The output is a self-contained HTML file** with interaction built in. Click a node and you get its upstream and downstream lists (Archify calls this the Semantic Passport). There is a guided view, deep links to individual nodes, trace animation along a path, dark and light themes, and export to PNG, SVG, and WebM.
- **It does not drop into a wiki.** You need somewhere that can open HTML: a browser, or hosting plus an embed. In Notion you end up inserting a PNG export, which loses the interaction.
- **It can import Mermaid.** Archify accepts Mermaid input and converts it, so an existing Mermaid diagram that has outgrown its layout can be redrawn in Archify without starting from scratch.

Archify is optimized for the diagram that a team keeps coming back to: the system map that people click through, not just glance at.

## Side by side

| | Mermaid | Archify |
|---|---|---|
| Input | Text grammar, automatic layout | JSON spec with explicit coordinates and routes |
| Quality control | None; a bad layout is hard to fix by hand | Validator rejects crossings, overlaps, and other rule violations |
| Output | Static SVG | Interactive HTML (click, deep link, trace, themes, export) |
| Embedding in a wiki | Native in Notion, GitHub, GitLab, Confluence | Needs a browser or hosting; PNG export for Notion |
| Effort to create | Minutes | Considerably more, but the result is deterministic |
| Comfortable scale | Up to a few dozen nodes | Large maps, tens of domains and up |
| Migration path | Starting point | Imports Mermaid |

## How to choose

The comparison is not "which one is better." It is a question of scale and of how the diagram will be used.

- **Small diagram, read inside a document:** Mermaid. A sequence diagram in a design doc, a flow in a README, a component sketch in a ticket. The ability to paste it straight into the wiki outweighs everything else.
- **Large map that people navigate:** Archify. Once a diagram becomes the thing engineers open to find out what depends on what, static SVG is not enough, and the layout has to stay readable as the system grows.
- **Already have a Mermaid diagram that stopped working:** use Archify's Mermaid import as the migration route. Keep the Mermaid source for the small views and move only the overview.

A reasonable team setup is to keep both. Mermaid stays the default for anything that lives in a page. Archify is reserved for the handful of diagrams that have grown past the point where auto-layout can cope, hosted somewhere the team can open them, with a PNG export placed in the wiki as a pointer.

## Conclusion

Mermaid trades control for convenience: you write the structure and accept whatever layout comes out, in exchange for a diagram that renders inside almost any document. Archify trades convenience for control: you specify the picture and a validator holds it to a standard, in exchange for a self-contained interactive artifact that needs a place to live.

Neither replaces the other. Reach for Mermaid first, and switch a diagram to Archify when it earns it, which is usually the moment the overview page stops being readable.
