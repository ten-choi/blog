---
title: "PostgreSQL Data Types (Borrowed Reference)"
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
NameAliasesDescription

[www.gurubee.net/lecture/2947](http://www.gurubee.net/lecture/2947)

<table style="border-collapse: collapse; width: 100%;" border="1"><tbody><tr><td>Bigint</td><td>int8</td><td>signed 8-byte integer</td></tr><tr><td>Bigserial</td><td>serial8</td><td>auto-incrementing 8-byte integer</td></tr><tr><td>bit [ (n) ]</td><td>fixed-length bit string</td></tr><tr><td>bit varying [ (n) ]</td><td>Varbit</td><td>variable-length bit string</td></tr><tr><td>Boolean</td><td>Bool</td><td>logical Boolean (true/false)</td></tr><tr><td>Box</td><td>rectangular box on a plane</td></tr><tr><td>Bytea</td><td>binary data ("byte array")</td></tr><tr><td>character [ (n) ]</td><td>char [ (n) ]</td><td>fixed-length character string</td></tr><tr><td>character varying [ (n) ]</td><td>varchar [ (n) ]</td><td>variable-length character string</td></tr><tr><td>Cidr</td><td>IPv4 or IPv6 network address</td></tr><tr><td>Circle</td><td>circle on a plane</td></tr><tr><td>Date</td><td>calendar date (year, month, day)</td></tr><tr><td>double precision</td><td>float8</td><td>double precision floating-point number (8 bytes)</td></tr><tr><td>Inet</td><td>IPv4, IPv6 host address</td></tr><tr><td>Integer</td><td>int, int4</td><td>signed four-byte integer</td></tr><tr><td>interval [ fields ] [ (p) ]</td><td>time span</td></tr><tr><td>Json</td><td>textual JSON data</td></tr><tr><td>Jsonb</td><td>binary JSON data, decomposed</td></tr><tr><td>Line</td><td>infinite line on a plane</td></tr><tr><td>Lseg</td><td>line segment on a plane</td></tr><tr><td>Macaddr</td><td>MAC (Media Access Control) address</td></tr><tr><td>Money</td><td>currency amount</td></tr><tr><td>numeric [ (p, s) ]</td><td>decimal [ (p, s) ]</td><td>exact numeric of selectable precision</td></tr><tr><td>Path</td><td>geometric path on a plane</td></tr><tr><td>pg_lsn</td><td>PostgreSQL Log Sequence Number</td></tr><tr><td>Point</td><td>geometric point on a plane</td></tr><tr><td>Polygon</td><td>closed geometric path on a plane</td></tr><tr><td>Real</td><td>float4</td><td>single precision floating-point number (4 bytes)</td></tr><tr><td>Smallint</td><td>int2</td><td>signed 2-byte integer</td></tr><tr><td>Smallserial</td><td>serial2</td><td>auto-incrementing 2-byte integer</td></tr><tr><td>Serial</td><td>serial4</td><td>auto-incrementing 4-byte integer</td></tr><tr><td>Text</td><td>variable-length character string</td></tr><tr><td>time [ (p) ] [ without time zone ]</td><td>time of day (no time zone)</td></tr><tr><td>time [ (p) ] with time zone</td><td>timetz</td><td>time of day, including time zone</td></tr><tr><td>timestamp [ (p) ] [ without time zone ]</td><td>date and time (no time zone)</td></tr><tr><td>timestamp [ (p) ] with time zone</td><td>timestamptz</td><td>date and time, including time zone</td></tr><tr><td>Tsquery</td><td>text search query</td></tr><tr><td>Tsvector</td><td>text search document</td></tr><tr><td>txid_snapshot</td><td>user-level transaction ID snapshot</td></tr><tr><td>Uuid</td><td>universally unique identifier</td></tr><tr><td>Xml</td><td>XML data</td></tr></tbody></table>
