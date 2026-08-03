---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: httpsig-algo
Protocols: HTTP
Arg: <algorithm>
Help: Algorithm for HTTP Message Signatures
Category: auth http
Added: 8.22.0
Multi: single
Experimental: yes
See-also:
  - httpsig-key
  - httpsig-keyid
  - httpsig-headers
Example:
  - --httpsig-key key.hex --httpsig-keyid "my-key" $URL
  - --httpsig-algo hmac-sha256 --httpsig-key secret.hex --httpsig-keyid "shared" $URL
---

# `--httpsig-algo`

Sign outgoing HTTP requests using RFC 9421 HTTP Message Signatures.

This option specifies which signing algorithm to use. Supported values are
**ed25519** and **hmac-sha256**. If not specified, **ed25519** is used. Any
other value causes curl to exit with an error.

HTTP Message Signatures are enabled when any of --httpsig-algo,
--httpsig-key, --httpsig-keyid or --httpsig-headers is given. When enabled,
--httpsig-key and --httpsig-keyid are required. Without any of these options
no signing is performed.

By default, the signed components are `method`, `authority`, `path`, and
`query` (when a query string is present). Use --httpsig-headers to override
the set of components included in the signature.
