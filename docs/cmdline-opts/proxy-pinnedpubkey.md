---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-pinnedpubkey
Arg: <hashes>
Help: FILE/HASHES public key to verify proxy with
Protocols: TLS
Category: proxy tls
Added: 7.59.0
Multi: single
See-also:
  - pinnedpubkey
  - proxy
Example:
  - --proxy-pinnedpubkey keyfile $URL
  - --proxy-pinnedpubkey 'sha256//ce118b51897f4452dc' $URL
---

# `--proxy-pinnedpubkey`

Use the specified public key file (or hashes) to verify the proxy. This can be
a path to a file which contains a single public key in PEM or DER format, or
any number of base64 encoded sha256 hashes preceded by 'sha256//' and
separated by ';'.

When negotiating a TLS or SSL connection, the server sends a certificate
indicating its identity. A public key is extracted from this certificate and
if it does not exactly match the public key provided to this option, curl
aborts the connection before sending or receiving any data.

Before curl 8.10.0 this option did not work due to a bug.
