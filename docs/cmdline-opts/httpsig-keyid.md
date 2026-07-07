---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: httpsig-keyid
Protocols: HTTP
Arg: <id>
Help: Key identifier for HTTP Message Signatures
Category: auth http
Added: 8.22.0
Multi: single
Experimental: yes
See-also:
  - httpsig-algo
  - httpsig-key
Example:
  - --httpsig-algo ed25519 --httpsig-key key.hex --httpsig-keyid "my-key" $URL
---

# `--httpsig-keyid`

The key identifier to include in the `Signature-Input` header when using
RFC 9421 HTTP Message Signatures with --httpsig-algo. This value appears
as the `keyid` parameter and allows the server to look up the correct
verification key.
