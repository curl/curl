---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: httpsig-headers
Protocols: HTTP
Arg: <components>
Help: Components to sign for HTTP Message Signatures
Category: auth http
Added: 8.20.0
Multi: single
See-also:
  - httpsig
  - httpsig-key
  - httpsig-keyid
Example:
  - --httpsig ed25519 --httpsig-key key.hex --httpsig-keyid "my-key" --httpsig-headers "@method @authority content-type" $URL
---

# `--httpsig-headers`

Space-separated list of components to include in the RFC 9421 HTTP Message
Signature. Derived components start with `@` (e.g. `@method`, `@authority`,
`@path`, `@query`). Regular header names are specified without `@` (e.g.
`content-type`, `content-digest`).

If not specified, the default set is `@method @authority @path` (plus `@query`
when a query string is present in the URL).
