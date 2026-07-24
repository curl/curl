---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: httpsig-key
Protocols: HTTP
Arg: <file>
Help: Key file for HTTP Message Signatures
Category: auth http
Added: 8.22.0
Multi: single
Experimental: yes
See-also:
  - httpsig-algo
  - httpsig-keyid
Example:
  - --httpsig-algo ed25519 --httpsig-key key.hex --httpsig-keyid "my-key" $URL
---

# `--httpsig-key`

Path to the key file used for RFC 9421 HTTP Message Signatures.

The file must contain a hex-encoded key on its first line. For **ed25519**,
this is the 32-byte private seed (64 hex characters). For **hmac-sha256**,
this is the shared secret. PEM files are not supported.

## Generating Ed25519 keys

With OpenSSL 3:

    openssl genpkey -algorithm ED25519 -out k.pem
    openssl pkey -in k.pem -outform RAW -out k.raw
    xxd -p -c 64 k.raw | tr -d '\n' > k.hex

Use `k.hex` with `--httpsig-key`.
