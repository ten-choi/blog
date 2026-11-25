---
title: "I Built a Chrome Extension for A-B Repeat on Audible"
labels: ["ai","productivity","career","developer","Archive"]
published: true
date: 2025-04-12T17:11:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "223740756856477549"
source: "archive"
archivePath: "_archive/dev/side-projects/chrome-extension/오디블.md"
---

## I Tried to Study English with Audible

If you're learning English, you've probably thought about this at least once: deciding to study English by listening to Audible, and subscribing.

After listening a few times, I found it less efficient than I expected. Just listening doesn't make things stick.

The problem was this pattern:

1. I listen
2. An unfamiliar word comes up
3. I look it up and go back to where I was
4. I want to replay that section over and over

So I looked through both the app and the website, but neither supported A-B repeat. It looked hard to do in the app, but on the web it seemed possible. I decided to build it myself as a Chrome extension.

## Features I Wanted

1. A-B repeat
2. Saving repeat sections
3. Buttons to jump a few seconds from a saved section
4. A top bar showing progress

## Development

I started with the core feature, A-B repeat, together with Claude. The feature itself came together quickly.

### The Core Problem: Looping Stalls Partway Through

The problem most worth writing down was that **the loop would stall around the second repetition**.

You'd think seeking with `audio.currentTime = startPoint` would just resume playback from there, but in practice it didn't.

#### Audible's Streaming Architecture


DRM (Digital Rights Management)
DASH (Dynamic Adaptive Streaming over HTTP)


HTMLMedia (HTMLMediaElement)
This is the `<video>` or `<audio>` tag itself that we see on websites.

2. MSE (Media Source Extensions)
This is the key part. Originally, a `<video>` tag could only play a single complete file such as an mp4, but with MSE it became possible to stitch chunks of data together in real time.



Audible doesn't play a single mp3 file in one go.

- It uses **DASH streaming**
- Split into **20-second segments**
- With **DRM (CENC)** applied

With this architecture, when a seek happens, the player internally has to do the following:

1. Fire a `seeking` event
2. Fetch the segment for the new position over the network
3. Fire a `seeked` event once ready
4. Continue playback

But after looping several times, there were cases where **the player's internal fetch stalled** after a seek. In that state, `readyState` stays at 1 and no `seeked` event arrives, so playback never resumes.

#### What `readyState` Values Mean

| Value | State |
|---|---|
| 0 | No information |
| 1 | Metadata only |
| 2 | Current frame playable |
| 3, 4 | Can play reliably |

If `readyState` stays at 1, it means the seek went through but the player is stuck without having fetched the segment it needs to actually play.

#### The Fix

While waiting for the `seeked` event, also watch `readyState`. If `readyState <= 1` persists for longer than a set time, set `currentTime` again to re-trigger the seek.

> **TL;DR:** Audible's DASH player can stop loading segments internally after repeated seeks. Don't rely on `seeked` alone — watch `readyState` too, and when it gets stuck, set `currentTime` again to retry the seek.
>
> 


targetAudio.currentTime = loopStart + (retryCount * 0.001);

In effect:

"If you seek to the exact same time, the player might not treat it as a new seek, so pass in a value that's ever so slightly different so it's recognized internally as a new request."

### The Other Features

Saving repeat sections (#2) and the seconds-jump buttons (#3) were relatively simple to build.

The progress top bar (#4) left something to be desired. I wanted a progress bar always visible at the top of the screen, like YouTube, but that's impossible with Chrome extension permissions. It needed desktop-application-level permissions, not browser-level ones.

Instead, I worked around it by opening a separate small web window. I use three monitors, so parking it in a corner was enough for checking in now and then.

## Not Publishing It

Searching around, a surprising number of people want this feature. I thought about publishing it, but releasing an Audible-related extension seemed like it could cause legal trouble, so I decided to keep it for personal use.

## What I Want to Try Next

Buying Kindle and Audible versions separately is a hassle, so I also tried preparing the text of the same book and converting the Audible audio with STT to show it like subtitles. But getting the STT output to follow along with the text in real time wasn't as smooth as I'd hoped.

To do it properly, I'd need features like these:

- Syncing the book reader's scroll to the reading pace via STT
- Saving unfamiliar English words and showing them floating, furigana-style

Technically, the hardest part is syncing the STT output with the text naturally. I'll need to think about it some more.
