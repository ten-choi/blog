---
title: "Encryption Notes"
labels: ["Archive"]
published: true
date: 2023-08-10T17:44:34+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 188
tistoryUrl: "https://yeolceo.tistory.com/188"
tistoryCategory: ""
tistoryTags: []
tistoryPostedAt: "2023-08-10 17:44:34"
language: en
bloggerPostId: "819037340695792523"
---
### What Is Encryption?

Encryption means turning data that needs protecting into a string, using a specific algorithm, so that users or developers can't make sense of it.

It keeps data that should stay hidden from being exposed, which prevents people from reverse-engineering your logic or API, or from mounting simple attacks.

### Two-Way vs. One-Way

A two-way algorithm produces ciphertext that can be decrypted.

A one-way algorithm produces ciphertext that can't be decrypted.

The classic example of one-way encryption is a hash.

### What Are Symmetric and Asymmetric Keys in Two-Way Encryption?

Symmetric encryption uses the same key to encrypt and decrypt.

Asymmetric encryption uses different keys to encrypt and decrypt.

Symmetric key (private key)  
The same key is used to encrypt and decrypt, so it must never leak.

Typical example: AES

Asymmetric key (public key)

The public key is used for encryption. It's slow, so it's inefficient for large amounts of data.

Typical example: RSA

AES-128

algorithm

PKCS#7 padding:

When the input to encryption/decryption isn't a multiple of the cipher block size, the empty space is filled in to reach that multiple. That filling is called padding.

The difference between PKCS#5 and PKCS#7:

PKCS#5 is fixed to an 8-byte cipher block size.

AA 07 07 07 07 07 07 07 - 1byte data + 7byte padding

AA BB 06 06 06 06 06 06 - 2byte data + 6byte padding

AA BB CC 05 05 05 05 05 - 3byte data + 5byte padding

That's how it pads to 8 bytes.

AES uses a 16-byte cipher block, and PKCS#7 covers block sizes up to 16 bytes, meaning it pads all the way up to 16 bytes in the same way.
