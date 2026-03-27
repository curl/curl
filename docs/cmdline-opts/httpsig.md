---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: httpsig
Protocols: HTTP
Arg: <algorithm>
Help: RFC 9421 HTTP Message Signatures
Category: auth http
Added: 8.21.0
Multi: single
See-also:
  - httpsig-key
  - httpsig-keyid
  - httpsig-headers
Example:
  - --httpsig ed25519 --httpsig-key key.hex --httpsig-keyid "my-key" $URL
  - --httpsig hmac-sha256 --httpsig-key secret.hex --httpsig-keyid "shared" $URL
---

# `--httpsig`

Sign outgoing HTTP requests using RFC 9421 HTTP Message Signatures.

The algorithm argument specifies which signing algorithm to use. Supported
values are **ed25519** and **hmac-sha256**.

This option requires --httpsig-key and --httpsig-keyid to also be set.

By default, the signed components are `@method`, `@authority`, `@path`, and
`@query` (when a query string is present). Use --httpsig-headers to override
the set of components included in the signature.
