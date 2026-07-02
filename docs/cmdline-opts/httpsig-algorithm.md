---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: httpsig-algorithm
Protocols: HTTP
Arg: <algorithm>
Help: Algorithm for HTTP Message Signatures
Category: auth http
Added: 8.21.0
Multi: single
Experimental: yes
See-also:
  - httpsig-key
  - httpsig-keyid
  - httpsig-headers
Example:
  - --httpsig-algorithm ed25519 --httpsig-key key.hex --httpsig-keyid "my-key" $URL
  - --httpsig-algorithm hmac-sha256 --httpsig-key secret.hex --httpsig-keyid "shared" $URL
---

# `--httpsig-algorithm`

Sign outgoing HTTP requests using RFC 9421 HTTP Message Signatures.

The algorithm argument specifies which signing algorithm to use. Supported
values are **ed25519** and **hmac-sha256**. Any other value causes curl to
exit with an error.

This option enables HTTP Message Signatures and requires --httpsig-key and
--httpsig-keyid to also be set. If --httpsig-key, --httpsig-keyid or
--httpsig-headers is given without --httpsig-algorithm, curl exits with an
error. Without any of these options no signing is performed.

By default, the signed components are `@method`, `@authority`, `@path`, and
`@query` (when a query string is present). Use --httpsig-headers to override
the set of components included in the signature.
