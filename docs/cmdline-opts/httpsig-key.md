---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: httpsig-key
Protocols: HTTP
Arg: <file>
Help: Key file for HTTP Message Signatures
Category: auth http
Added: 8.21.0
Multi: single
See-also:
  - httpsig
  - httpsig-keyid
Example:
  - --httpsig ed25519 --httpsig-key key.hex --httpsig-keyid "my-key" $URL
---

# `--httpsig-key`

Path to the key file used for RFC 9421 HTTP Message Signatures.

The file must contain a hex-encoded key on its first line. For **ed25519**,
this is the 32-byte private seed (64 hex characters). For **hmac-sha256**,
this is the shared secret. PEM files are not supported.

## Generating Ed25519 keys

With OpenSSL 3:

~~~bash
openssl genpkey -algorithm ED25519 -out k.pem
openssl pkey -in k.pem -outform RAW -out k.raw
xxd -p -c 64 k.raw | tr -d '\n' > k.hex
~~~

Use `k.hex` with `--httpsig-key`. The same hex file works with curl built
against OpenSSL or wolfSSL.

For wolfSSL builds, the library needs `--enable-ed25519` at build time; wolfSSL
has no `genpkey`-style CLI. Generate the hex seed with OpenSSL as above, or with
wolfCrypt (`wc_ed25519_make_key()` / `wc_ed25519_export_private_only()`).
