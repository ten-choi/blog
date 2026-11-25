---
title: "PostgreSQL Data Types Cheat Sheet"
labels: ["DB","rdb","Archive"]
published: true
date: 2020-09-16T14:45:15+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 47
tistoryUrl: "https://yeolceo.tistory.com/47"
tistoryCategory: "DB/rdb"
tistoryTags: []
tistoryPostedAt: "2020-09-16 14:45:15"
language: en
bloggerPostId: "3713671167873156959"
---
A quick, grouped cheat sheet of the PostgreSQL data types I reach for most often. Aliases are the alternative names PostgreSQL accepts for the same type.

## Numbers

| Type | Alias | Notes |
|---|---|---|
| `smallint` | `int2` | 2-byte signed integer (-32,768 to 32,767) |
| `integer` | `int`, `int4` | 4-byte signed integer — the usual default |
| `bigint` | `int8` | 8-byte signed integer — use for IDs that may grow large |
| `numeric(p, s)` | `decimal(p, s)` | Exact decimal; use for money and anything that must not round |
| `real` | `float4` | 4-byte floating point (inexact) |
| `double precision` | `float8` | 8-byte floating point (inexact) |
| `money` | | Currency amount tied to the locale; `numeric` is usually the safer choice |

### Auto-increment

| Type | Alias | Notes |
|---|---|---|
| `smallserial` | `serial2` | Auto-incrementing `smallint` |
| `serial` | `serial4` | Auto-incrementing `integer` |
| `bigserial` | `serial8` | Auto-incrementing `bigint` |

On PostgreSQL 10+ you can also use `integer GENERATED ALWAYS AS IDENTITY`, which is the SQL-standard way to do the same thing.

## Text

| Type | Alias | Notes |
|---|---|---|
| `char(n)` | `character(n)` | Fixed length, padded with spaces |
| `varchar(n)` | `character varying(n)` | Variable length with a maximum |
| `text` | | Variable length, no limit — in PostgreSQL it performs the same as `varchar` |

## Date and time

| Type | Alias | Notes |
|---|---|---|
| `date` | | Calendar date (year, month, day) |
| `time` | | Time of day without a time zone |
| `time with time zone` | `timetz` | Time of day with a time zone (rarely useful) |
| `timestamp` | | Date and time without a time zone |
| `timestamp with time zone` | `timestamptz` | Date and time stored as UTC — usually what you want |
| `interval` | | A span of time, e.g. `'3 days 2 hours'` |

## Boolean and binary

| Type | Alias | Notes |
|---|---|---|
| `boolean` | `bool` | `true` / `false` / `null` |
| `bytea` | | Binary data (byte array) |
| `bit(n)` | | Fixed-length bit string |
| `bit varying(n)` | `varbit` | Variable-length bit string |

## JSON, XML, and IDs

| Type | Notes |
|---|---|
| `json` | Stores the JSON text as is |
| `jsonb` | Stores parsed binary JSON — supports indexing; prefer this over `json` |
| `xml` | XML data |
| `uuid` | Universally unique identifier |

## Network

| Type | Notes |
|---|---|
| `inet` | IPv4 or IPv6 host address |
| `cidr` | IPv4 or IPv6 network address |
| `macaddr` | MAC address |

## Geometry

`point`, `line`, `lseg` (line segment), `box`, `path`, `polygon`, and `circle` cover basic 2D shapes. For real GIS work, use the PostGIS extension instead.

## Full-text search and internals

| Type | Notes |
|---|---|
| `tsvector` | A document prepared for text search |
| `tsquery` | A text search query |
| `pg_lsn` | PostgreSQL log sequence number |
| `txid_snapshot` | Transaction ID snapshot |

## Reference

- [PostgreSQL documentation — Data Types](https://www.postgresql.org/docs/current/datatype.html)
