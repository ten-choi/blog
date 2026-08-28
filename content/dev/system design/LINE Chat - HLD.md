---
title: "System Design Mock Interview - HLD: \"Design a Messenger Like LINE\""
labels: ["System Design", "HLD", "Real-Time", "Messaging", "Tech Interviews"]
published: false
date:
readerComments: "ALLOW"
---

> Most web services are request-response: a request comes in, you answer it, you're done. A messenger belongs to a different archetype.
>
> A messenger is **"persistent-connection"** — it's not request-response; **the connection itself is state**. And the messages flowing over that connection can never be lost, must stay in order within a conversation, and the recipient might be offline on the subway. It's a 45-minute whiteboard interview. Let's go.

# The HLD Mock Interview — "Design a Messenger Like LINE"

## 0. Before We Start — What Makes a Messenger Different

| | **A typical web service** (feeds, e-commerce, ticketing) | **A messenger (this post)** |
|---|---|---|
| Shape of the load | Requests — QPS is the unit of scale | **50 million concurrent connections — the load is connections, not requests** |
| Nature of the data | Durable rows served on demand | **Messages can never be lost + in-order within a conversation** |
| Consistency | One tier fits most data | **Two tiers: delivery guarantees (messages) vs eventual (read receipts, presence)** |
| Where it's won or lost | Caching, queueing, sharding | **Connection gateway + store-and-forward** |

Check the clock first — for a 45-minute interview, a solid split is 5 min requirements / 5 min back-of-envelope math / 5 min API & data model / 15 min architecture / 10 min deep dive / 5 min wrap-up.

---

## 1. Requirements First — No Boxes Yet

**Interviewer** — Here's today's problem. **Design a messenger like LINE.**

**Me** — Let me narrow the scope first. Can I take the core features to be **1:1 chat, group chat, and read receipts / online presence**? Excluding calls, the sticker shop, and the timeline.

**Interviewer** — Good. Let's cap groups at **500 members**.

**Me** — The non-functional side feels like the real body of this problem. Three things to confirm. First, **message loss is absolutely unacceptable** — correct? Second, **order within a conversation** must be preserved. Third — this is a mobile messenger, so **the recipient being offline is the norm, not the exception**. Subways, battery saver mode, force-killed apps. Can I design with that as a premise?

**Interviewer** — All three, yes. Delivery latency should be within a few hundred milliseconds when online, and for scale, assume **a country where the entire population uses it, like Japan**.

> 💡 **Coaching note** — The first point scored in this problem is raising "the recipient may be offline" **from the candidate's side**. With a web-service mindset, "a request comes in, we respond" is the default — but in a messenger, **the send must succeed even when the receiver isn't there**. Naming this asymmetry at the requirements stage makes the store-and-forward that follows justify itself.

---

## 2. Back-of-Envelope Math — 50 Million Connections Are the Real Body

**Me** — Let me run the numbers. With 200M MAU and peak concurrency at 25%, that's **50 million concurrent connections**. And this is where the problem reveals its true identity — a messenger is a system where the server has to **speak to the client first**. HTTP request-response gives the server no way to initiate, so **holding 50 million persistent connections (WebSocket) IS the body of this system**.

If a well-tuned server holds a few hundred thousand connections, we need **hundreds of connection servers** just for that. Which immediately raises the next problem — to push a message to user B, we need to know **which of those hundreds of servers B is attached to**. So a **session registry** managing "user_id → connected server" falls out as a mandatory component.

The messages themselves, by contrast, are light. Hundreds of thousands per second, but mostly a few hundred bytes of text — this isn't a media-storage problem measured in petabytes. **The center of gravity of the load is connections, not data** — that's this problem's true identity.

> 💡 **Coaching note** — The point of back-of-envelope math is to extract the one line that justifies your next decision — and here, "**50 million concurrent connections**" is that line: it justifies the gateway tier and the session registry. Don't just extract "how many QPS" from the math — extract **what kind of load it is** (requests? connections? a stream?).

---

## 3. API and Data Model — It's a Protocol, Not REST

**Me** — Let me write down the contract. This system's contract isn't a list of REST endpoints — it's a **message protocol over WebSocket**.

```
Client → Server : SEND     (client_msg_id, channel_id, payload)
Server → Client : ACK      (client_msg_id, server_msg_id, seq)    ← the "it's stored" promise
Server → Client : DELIVER  (server_msg_id, channel_id, seq, payload)
Both directions : RECEIPT  (channel_id, last_read_seq)             ← read receipts
Both directions : PRESENCE (user_id, online/offline)               ← online status
```

The data model looks like this:

```
channels  (id, type: DIRECT/GROUP, member_ids[])
messages  (channel_id, seq, sender_id, payload, created_at)   -- PK (channel_id, seq)
          seq = per-channel monotonically increasing sequence ← the root of ordering
Session registry → Redis: user_id → {gateway_id, device_id}   -- connection state, TTL
```

The key is `seq`. The server issues **a monotonically increasing number — 1, 2, 3… per conversation (channel)** — at storage time. Clients sort by this number, and if a number is skipped, they can detect "there's a missing message."

**Interviewer** — Hold on. Do we really need WebSocket? Can't the client just **poll a REST endpoint every second**?

**Me** — Let me answer with numbers. If 50 million concurrent users poll every second, that's **50 million QPS by itself** — and over 99% of it is empty "no new messages" responses. The server spends world-record traffic on empty responses, and on mobile, every request wakes the radio and **burns battery**. And you still lose latency equal to the polling interval — 500ms on average. A persistent connection solves all three: traffic scales with actual messages, pushes are instant, and an idle connection costs only a few heartbeat bytes.

> 💡 **Coaching note** — "Why not polling?" is the stock follow-up in this problem, and the caliber of the answer is decided by **numbers**. The moment you say "50 million QPS of empty responses" instead of "because it's slow," the back-of-envelope math from section 2 pays itself back. In many systems a persistent connection is one option among several; in a messenger it's **the condition for the system to exist at all**.

---

## 4. Body Part ① — The Connection Gateway Tier

**Me** — The first body of the architecture: the tier that holds the connections. Hundreds of **connection gateways** each hold a few hundred thousand WebSockets, and on every connect/disconnect they record `user_id → gateway_id` in the session registry (Redis).

Message delivery then becomes **server-to-server routing** on top of this. When A sends to B: A's gateway → message service (store) → look up B's gateway in the registry → **forward to the gateway B is attached to** → that gateway pushes into B's socket. The gateways stay a thin layer doing only auth and connection management; all business logic lives in the stateless services behind them — the stateful tier should be as simple as possible.

**Interviewer** — What happens when **one of those gateway servers dies** and takes its 500,000 connections with it?

**Me** — 500,000 people get disconnected at once — and that has to be **routine, designed-for behavior, not an incident**. Three layers of response:

1. **Client auto-reconnect** — disconnected clients reattach through the load balancer to a live gateway. But if 500,000 retry at the same instant, that's another spike of its own, so we scatter the reconnect storm with **exponential backoff plus jitter (random delay)**.
2. **Registry refresh** — on reconnect, the registry is overwritten with the new gateway, and the dead server's entries expire naturally via TTL.
3. **Missed-message sync** — the messages from those few disconnected seconds couldn't be pushed, but **they're in storage**. On reconnect the client sends its "last seq per channel," and the server sends down everything after it.

So the principle is: **make connections safe to lose, and make messages impossible to lose.**

> 💡 **Coaching note** — The core of this answer is **separating connection durability from data durability**. Connections are a volatile resource — "recovers quickly" is good enough — while messages are a durable resource guarded by storage. A design without this separation collapses at the follow-up: "what if the gateway is holding messages when it dies?"

---

## 5. Body Part ② — No Loss, In Order

**Me** — The second body, and the heart of this problem. "Absolutely no loss" is one sentence, but the implementation is a chain of discipline. The principle is **store-and-forward** — **always store first; only then attempt delivery**.

1. **Storage comes first** — on receiving SEND, we write to the messages table and issue a seq, and only then ACK the sender. The ACK doesn't mean "the other person got it" — it's the promise that "**the server now owns this**." From that moment, whether the recipient is offline or the gateway dies, the message is safe.
2. **Delivery and retransmission** — we forward the stored message to the recipient's gateway and wait for **the receiving client's ACK**. No ACK means retransmit, and the duplicates that retransmission creates are **removed on the receiving side by message ID** — the classic idempotency principle: retransmit shamelessly, dedupe at the receiver.
3. **Order and gaps** — clients sort by seq, and if 7 arrives after 5, they instantly know 6 is missing. The missing range gets re-requested from the server.
4. **Detour when offline** — if the recipient isn't on any gateway, we don't give up on delivery; we route around it with an **APNs/FCM push notification** saying only "you have a message." The body syncs from storage when the user opens the app and connects. The push is a doorbell that wakes you up; the truth always lives in storage.

**Interviewer** — Do read receipts and presence get the same guarantee? Those are also hundreds of thousands per second.

**Me** — No — **we split them into tiers**. Nobody gets hurt if a read receipt is a few seconds late or an online indicator flickers once — this is data where the next update overwrites any loss. So that side flows as eventual consistency with no retransmission, and PRESENCE is **throttled** so connect/disconnect flapping doesn't fire every event. Guarantees are expensive, so **the expensive guarantee goes to messages only**.

> 💡 **Coaching note** — The scoring point of this section is dividing, unprompted, the data flowing through the same pipe into **two tiers**: messages = no loss, ordered, retransmitted (expensive); receipts/presence = loss-tolerant, eventual, throttled (cheap). The principle in one line: "**flicker is approximate, chat bubbles are exact**."

---

## 6. Group Chat and the Full Picture — The Cap Protects the Design

**Interviewer** — What about group chat? One message to a 500-member room is 500 deliveries.

**Me** — Yes, structurally it's classic **fan-out on write** — store one message, then replicate it into as many delivery jobs as there are members. But there's a decisive difference from, say, a feed system pushing a celebrity's post to followers. A feed's fan-out is unbounded — one account can have 50 million followers, which forces escape hatches like hybrid push/pull — but here, **the requirements gave us a hard cap of 500**. Worst-case fan-out is bounded at 500, so a single Push strategy holds all the way. **The cap protects the design** — which means if product asks "why can't groups be unlimited?", I can answer with an architectural reason.

Putting every decision so far on one page:

```
Client (mobile)                          Client (recipient)
   │ WebSocket: SEND                        ▲ DELIVER / APNs·FCM push if offline
   ▼                                        │
Connection gateway tier (hundreds of servers, ~100Ks of connections each)
   │  connect/disconnect ──▶ Session registry (Redis: user_id → gateway_id, TTL)
   ▼
Message service ─ ① store first (messages: channel_id + monotonic seq) → then ACK
   │
   └─▶ Kafka (new-message event)
         ├─▶ Delivery router ─ look up registry → push to recipient's gateway
         │                     └ groups: fan out per member (capped at 500)
         └─▶ Push service ─ APNs/FCM to offline recipients

Reconnect sync:      client presents "last seq per channel" → storage sends the rest
Receipts & presence: separate path, eventual consistency + throttling (no retransmission)
```

> 💡 **Coaching note** — The same word, fan-out, splits into different designs depending on **whether there's a cap**. Unbounded (follower counts) means you need an escape hatch into hybrid/async; bounded (group of 500) means the simple strategy holds to the end. One number in the requirements swings the entire complexity of the architecture — that's why you pin down the cap back in section 1.

---

## 7. "Where Would You Improve First?" — Version 2

**Interviewer** — We have time left. What are the limits of this design?

**Me** — I'd point at three spots.

1. **Multi-device sync** — we've assumed one connection per user, but LINE logs in on a phone and a PC simultaneously. The session registry expands to `user_id → [connections per device]`, and delivery becomes a per-device fan-out — but the key is **keeping a separate "how far have I received" cursor (last seq) per device**. Since we already laid down per-channel seq, we only need to multiply cursors — the section 5 decision pays off here.
2. **End-to-end (E2E) encryption** — like the real LINE's Letter Sealing: push encryption/decryption down to the client, so **the server only relays envelopes it cannot open**. This puts big constraints on the server design — you have to explicitly accept the trade-off of giving up server-side search and content filtering.
3. **Regional gateway placement** — placing gateways in each user-dense country (Japan, Taiwan, Thailand) cuts connection round-trip latency, and the blast radius from section 4's failures gets isolated per region. Whether to also partition storage regionally, I'd decide based on how often conversations cross borders.

> 💡 **Coaching note** — Version-2 candidates always come from **"the hidden assumptions of my design."** The "one connection per user" assumption is broken by multi-device; the "server can read the payload" assumption is broken by E2E; the "gateways in one region" assumption is broken by global traffic. If you can enumerate your assumptions yourself, the limits enumerate themselves.

---

## 8. Interview Retro — What Was Actually Being Graded

1. **Requirements gathering** — beyond no-loss and ordering, raised "the recipient is usually offline" first
2. **Back-of-envelope math** — from "50 million concurrent connections," identified the load as connections and derived the gateway tier + session registry
3. **API & data model** — a WebSocket protocol (SEND/ACK/RECEIPT/PRESENCE) instead of REST, per-channel monotonic seq, and argued against polling with numbers
4. **Architecture** — separated the durability of gateways (connections) from the message service (data); store-and-forward
5. **Trade-off negotiation** — answered gateway failure with backoff + jitter and storage sync, and split receipts/presence into a second tier
6. **Foresight** — named the breaking points of the hidden assumptions: multi-device cursors, E2E encryption, regional placement

If you take one thing from this problem, take its archetype. The messenger is the **persistent-connection** type — the problem of **carrying data you must not lose over connections you will lose** — and its answers are always the same family: persistent connections, store-and-forward, ACKs and idempotency. When you meet a new design problem, ask first what kind of load it carries — requests, contention, streams, or connections — and half the architecture picks itself.

---

### 📝 TL;DR

> **"Messenger design is the problem of separating two durabilities — make connections safe to lose (reconnect + backoff + registry), and make messages impossible to lose (store first, deliver second — store-and-forward)."**

---

## Next Up

The interviewer follows up — "That message delivery. Care to design it as classes?" Continued in the [LINE Chat LLD post](<./LINE Chat - LLD.md>).
