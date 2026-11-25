---
title: "[ UrlDesign ] REST APIs and URL Design"
labels: ["Architecture","Archive"]
published: true
date: 2023-10-16T13:25:23+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 194
tistoryUrl: "https://yeolceo.tistory.com/194"
tistoryCategory: "Architecture/architecture"
tistoryTags: []
tistoryPostedAt: "2023-10-16 13:25:23"
language: en
bloggerPostId: "8473492126687472379"
---
In search of the ideal REST API and URL design, from a backend developer's point of view...

## What Is a REST API?

asdf

## REST API Design Rules

1.  URLs should use nouns rather than verbs.
2.  Use lowercase rather than uppercase.
3.  Use singular nouns for document names. (What exactly is a "document name"?)
4.  Use plural nouns for collection names.
5.  Store names should apparently be plural nouns too. What's a "store"?

## Goals of URL Design

1.  Keep URLs short, with the minimum needed as a clue.
2.  Make them descriptive, so you can infer the role of the API or page.
3.  Make them easy for search filters like Google's to pick up.

## Technical Basics of URL Design

1.  Be descriptive. An ideal URL uses keywords that match the page's content, giving search engines and users a clue about what's inside. For English-speaking audiences, say I'm searching for typescript, but the URL is

Separate words in URLs with hyphens, not underscores.

When searching on Google, given typescript, type-script, and type\_script, a hyphen is treated like a space,

but \_ is treated as part of the word. So when it comes to search terms, \_ looks like a disadvantage.

typescript

Design examples

Use lowercase rather than uppercase.

Don't put a trailing /. But Python's Django does, doesn't it?

Use a dash (-) instead of \_. This one's subtle.

Don't include file extensions in the URI. That one's obvious.

Don't include actions, i.e. post, delete, and so on. That doesn't mean "post" in the domain sense of publishing a blog post; it means don't write CRUD operations into the URL.

## Design with Pagination Best Practices in Mind

Google says every URL in a paginated set should share the same URL format with a single changing variable (e.g. **example.com/category/page-1, example.com/category/page-2**). Read more in the [pagination SEO best practices guide](https://www.deepcrawl.com/knowledge/technical-seo-library/pagination-seo-guide/).  
 So with pagination, it's fine to append a number at the end like that. I'm not sure whether the URL gets redirected, since it's the URL shown on the frontend.

## Keep Mobile and Desktop URLs Consistent

If you have a separate website for mobile, it's best to keep each site's URLs as consistent with desktop as possible, so it's easier to add rel alternate tags on desktop pages pointing to the mobile pages. See Google Developers for details. Hosting the mobile site on a subdomain (e.g. **m.example.com**) lets you keep the URL paths identical.

-   Case mismatch: /news and /NEWS
-   Trailing slash mismatch: /news/ and /news
-   Duplicate default paths: example.com and example.com/index.html
-   Duplicate URL formats (unfriendly vs. friendly): example.com/category/subcategory/page.html and example.com/page
-   Inconsistent ordering: example.com/category-1/subcategory/page-1 and example.com/category-2/page-1
-   HTTP/HTTPS/alias domains
-   Broken internal links that repeat a path more than once. These URLs are a common source of duplication, so Google can't crawl or index them.
-   Session IDs: Google treats these as separate URLs and tries to crawl every single version as its own page, which hurts crawl efficiency. Keep dynamic or session-based values out of the URL. If that isn't possible, use the URL Parameters setting in Search Console (under Crawl > URL Parameters) to make sure they're excluded from Googlebot's crawl.

Going from collection to identify

For example, “customers” is a collection resource and “customer” is a singleton resource (in a banking domain).

We can identify “customers” collec

References

1.  [Link](https://www.lumar.io/blog/best-practice/guide-to-url-design/)
2.  Link
