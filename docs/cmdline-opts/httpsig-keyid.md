---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: httpsig-keyid
Protocols: HTTP
Arg: <id>
Help: Key identifier for HTTP Message Signatures
Category: auth http
Added: 8.20.0
Multi: single
See-also:
  - httpsig
  - httpsig-key
Example:
  - --httpsig ed25519 --httpsig-key key.hex --httpsig-keyid "my-key" $URL
---

# `--httpsig-keyid`

The key identifier to include in the `Signature-Input` header when using
RFC 9421 HTTP Message Signatures. This value appears as the `keyid` parameter
and allows the server to look up the correct verification key.
