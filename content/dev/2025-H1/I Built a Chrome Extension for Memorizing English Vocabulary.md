---
title: "I Built a Chrome Extension for Memorizing English Vocabulary"
labels: ["ai","productivity","career","developer","Archive"]
published: true
date: 2025-04-07T09:01:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "4288018094380370598"
source: "archive"
archivePath: "_archive/dev/side-projects/chrome-extension/영단어외우기시스템.md"
---





I built a study tool as a Chrome extension.

For the DB, there are free services that usually let you use up to 1GB for free.
I considered using one, but some people use GitHub Gist as a DB, and that looked good too.
For simple features you can skip implementing a DB entirely and get CRUD from a text store with just an API and a token.



For dictionary lookups, there's the free Dictionary API,
and there was also a dictionary API you can use once you request a token.
Requesting one takes 7 days, and while I was waiting for it
I tried Gemini's free LLM tokens, which turned out to be pretty good, so I went with that.
Using an LLM just for dictionary lookups may be wasteful, but the performance is not bad and it's free.


It conflicted with an existing app called Trancy. I thought about using both together, but decided to drop Trancy.


I added the things I wanted bit by bit.
I needed a furigana-like feature that writes the meaning in Korean above the word so it's easy to understand,

and I wanted a button to pop up when I drag-select text, like in Trancy.

And when looking up an English word, if it was slightly changed from its base form because of past tense or third person, it interprets and saves the base form, while idioms of two or more words get saved as the idiom itself.


After a few rounds of testing while developing with AI, the development was done in no time,
with just a few more tests and tweaks afterwards.

It's a Chrome extension you use by entering two tokens: one for Gemini and one for GitHub Gist.


On Android, I decided to build a book-reading app with RN and Expo — an Android version of the book that plays the same role as voca-pin.
AI builds most of the UI for you, so now it feels like I only have to touch the internal details.


If I build it that way on Android, I can read books both on the web and on mobile.


At first I wanted an app that would always be running on mobile, so that whenever an English word I'd saved appeared on screen, its meaning would float above it.
But always-on OCR isn't a good approach, for performance and for battery, and triggering it with a button only when needed is inconvenient.
I also considered using Android's Accessibility Service to intercept text data and stack another layer on the screen to show meanings, but positioning the meanings is complicated, and when I asked myself whether I'd actually use it after building it,
I figured the only use that would stick is while reading books; otherwise, when I want to study English, it's more efficient to just use the apps I already use.




So I went ahead with RN, which I'd tried a little before.
Coming back to it after a long time:

It doesn't support Node 24
Along the way I found it supports 18
I installed Expo to test, and it got stuck loading forever

Copying the error logs shown on Android over to the AI was a pain


Even though I know JS and TS reasonably well, have done React, and have a bit of experience with React Native,
I concluded that with AI, Flutter would be more practical.

I started a full switch to Flutter.
Running it in Chrome makes simple tests easy, for starters.

When developing with AI, Flutter is much faster and more convenient.
I'm testing on Android and revising as I go.

So I built the app with Flutter.
It had three features: a book reader that reads txt files, an unknown-words list, and settings.

But looking at the unknown-words list didn't give me the feel I wanted.

There's an English vocabulary app I usually study with, and it's much more effective, so I decided to change it to work like that.


Create a Google Sheets service account as a credential at https://console.cloud.google.com/

Share the spreadsheet with my service account and set it as an editor
Then generate a JSON key in the Keys tab

and I used that JSON to edit the spreadsheet.

The editing itself worked without a problem. The biggest problem here was this:

GitHub Gist and Google Sheets are both good features, and both are free.
But if you try to use them as a DB, both are a hassle for an individual to set up.

I was torn. Gist seems a bit easier, but either way it's hard.

But if I provided the DB myself, it would defeat the purpose,
since the whole idea is to combine each person's free allowances so they can study for free.

In that sense I decided Sheets would be better, because
spreadsheets are more familiar to regular people (GitHub is basically for developers only),
and since the data stays as a spreadsheet, anyone who wants to print it can.

It's true that the number of values you have to enter goes up, so that's also a barrier to entry.

A Gemini API token plus a Google service account and access-info JSON?
It's hard. But for people who only want to study a little, half-heartedly, there are plenty of other apps out there,

and if there are people who want to study the same way I do, I think it's a pretty good way to learn.
And it's free, which is really nice.


That's what I thought as I happily developed it, but what came out in the end was:

client_email, private_key, token_uri, spreadsheet id
— these 4 plus the Gemini token have to be entered in both the extension and the mobile app.
This is really bad. Even entering the current 2 is probably annoying, and now the process is more complicated and there are more things to copy and paste.
Pretty bad.

Honestly, it'd be better to do it on GitHub, even if regular users don't know GitHub.


This is truly the worst user experience... GitHub Gist is the right call. At least it lets me keep it to 2 tokens.

If you're a developer, you set it up cleanly once and keep using it, but for a regular person
it's a real pain.


Back to GitHub Gist. Goodbye, spreadsheet... if I were the only one using it, you'd have been the better choice...

Of course, with Gist you still have to enter the ID of the gist you create.
That's inconvenient too, but still easier than client ID this and that...


Then I decided to add example sentences for the English words, for studying in the app.

And I need to add a language selector. I obviously learn in my own language, so that's how I built it, but

even if all the default explanations are in English, the explanations when studying English vocabulary need to be in your native language.



Also, do I even need to store the GitHub Gist ID? I can just do a full scan with the token, order by ID, manage 4 gists in that order, and save or fetch data from them.


On Android, I finished all the font-tuning work.

And while doing detailed development the way I wanted, I used Claude Sonnet 4.6, and it came out exactly the way I wanted.

The bottom sheet and everything else are just right.

I hope lots of people use it.
