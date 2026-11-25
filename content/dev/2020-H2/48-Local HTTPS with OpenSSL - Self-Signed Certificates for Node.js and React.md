---
title: "Local HTTPS with OpenSSL: Self-Signed Certificates for Node.js and React"
labels: ["nodejs","security","SSL","OpenSSL","Archive"]
published: true
date: 2020-09-17T10:37:07+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 48
tistoryUrl: "https://yeolceo.tistory.com/48"
tistoryCategory: ""
tistoryTags: []
tistoryPostedAt: "2020-09-17 10:37:07"
language: en
bloggerPostId: "1051935676625125367"
---
I needed HTTPS on my local Node.js server and React dev server, so I made a self-signed certificate with OpenSSL.
A self-signed certificate is only for development and testing. Browsers won't trust it, so for a real service you need a certificate from a CA (e.g. Let's Encrypt).

## Getting OpenSSL

- **macOS / Linux:** usually already installed. Check with `openssl version`.
- **Windows:** Git for Windows ships with OpenSSL, so you can run it from Git Bash. You can also install a standalone build.

## The Quick Way: One Command

For local development, this single command is all you need:

```bash
openssl req -x509 -newkey rsa:4096 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=localhost"
```

- `-x509`: create a self-signed certificate instead of a signing request
- `-newkey rsa:4096`: create a new 4096-bit RSA key at the same time
- `-nodes`: don't encrypt the key (no passphrase). Drop this option if you want one.
- `-subj "/CN=localhost"`: skip the interactive questions

You get two files: `key.pem` (private key) and `cert.pem` (certificate).

## Using It in Node.js (Express)

```js
const fs = require('fs');
const https = require('https');
const express = require('express');

const app = express();
const sslPort = 5050;

const options = {
  key: fs.readFileSync('./ssl/key.pem'),
  cert: fs.readFileSync('./ssl/cert.pem'),
  // passphrase: process.env.SSL_PASSPHRASE, // only if your key is encrypted
};

https.createServer(options, app).listen(sslPort, () => {
  console.log(`[HTTPS] Server started on port ${sslPort}`);
});
```

If your key has a passphrase, read it from an environment variable. Don't hard-code it in the source.

## Using It with the React Dev Server (CRA)

Start the dev server with HTTPS:

```bash
# Windows (cmd)
set HTTPS=true&&npm start

# macOS / Linux
HTTPS=true npm start
```

If the React app proxies API calls to the HTTPS Node server above, add `secure: false` to the proxy settings (`src/setupProxy.js`).
Without it, the proxy rejects the self-signed certificate.

```js
const { createProxyMiddleware } = require('http-proxy-middleware');

module.exports = function (app) {
  app.use(
    '/api',
    createProxyMiddleware({
      target: 'https://localhost:5050',
      changeOrigin: true,
      secure: false, // accept the self-signed certificate
    })
  );
};
```

## The Long Way: Step by Step

If you want to understand each piece, or you need a CSR for a real CA, here are the steps one by one.

### 1. Create a Private Key

```bash
openssl genrsa -out private.key 2048
```

This is the secret half of the key pair. **Never commit it or post it anywhere.**

### 2. Extract the Public Key (Optional)

```bash
openssl rsa -in private.key -pubout -out public.key
```

### 3. Create a CSR (Certificate Signing Request)

A CSR holds the information a CA needs to issue a certificate.

```bash
openssl req -new -key private.key -out private.csr
```

It asks for the following fields:

| Field | Example |
|---|---|
| Country Name (2-letter code) | KR |
| State or Province Name | Seoul |
| Locality Name (city) | Seoul |
| Organization Name | My Company |
| Organizational Unit Name | Dev |
| Common Name | www.example.com |
| Email Address | (optional) |

The **Common Name** must be the domain where the certificate will be used. Don't include `http://`, `https://`, a port, or a path.
You can leave the "challenge password" and "optional company name" blank.

### 4. Create a Self-Signed Certificate (CRT)

```bash
openssl x509 -req -days 365 -in private.csr -signkey private.key -out mycert.crt
```

### 5. Use a Config File to Skip the Questions

Typing the same answers every time gets old. Put them in a config file instead.
Modern browsers also require `subjectAltName` (SAN), not just the Common Name, so add it here.

`test.conf`:

```ini
[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
C = KR
ST = Seoul
L = Seoul
O = My Company
OU = Dev
CN = localhost

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
```

```bash
# CSR from the config
openssl req -new -key private.key -out private.csr -config test.conf

# Certificate with the SAN extension included
openssl x509 -req -days 365 -in private.csr -signkey private.key -out mycert.crt \
  -extfile test.conf -extensions req_ext
```

Without `-extfile ... -extensions req_ext`, the certificate is created without the SAN, and Chrome will reject it.

## Handy OpenSSL Commands

```bash
# Show what's inside a certificate
openssl x509 -text -noout -in mycert.crt

# Convert a CRT (DER) to PEM
openssl x509 -in mycert.crt -inform DER -out mycert.pem -outform PEM

# Check that a key and certificate match (the two hashes should be the same)
openssl x509 -noout -modulus -in mycert.crt | openssl md5
openssl rsa  -noout -modulus -in private.key | openssl md5
```

## Summary

- For local HTTPS, the one-line `openssl req -x509 ...` command is enough.
- Node: pass `key` and `cert` to `https.createServer()`.
- React proxy to a self-signed server: add `secure: false`.
- Add `subjectAltName` or modern browsers will reject the certificate.
- Keep private keys and passphrases out of your code and out of your posts.

References

- [blusky10.tistory.com/352](https://blusky10.tistory.com/352)
- [http://namjackson.tistory.com/24](http://namjackson.tistory.com/24)
