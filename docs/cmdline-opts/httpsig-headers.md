---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: httpsig-headers
Protocols: HTTP
Arg: <components>
Help: Components to sign for HTTP Message Signatures
Category: auth http
Added: 8.22.0
Multi: single
Experimental: yes
See-also:
  - httpsig-algo
  - httpsig-key
  - httpsig-keyid
Example:
  - --httpsig-algo ed25519 --httpsig-key key.hex --httpsig-keyid "my-key" --httpsig-headers "method authority content-type:" $URL
---

# `--httpsig-headers`

Space-separated list of components to include in the RFC 9421 HTTP Message
Signature when using --httpsig-algo. Derived components are given as bare
names: `method`, `authority`, `path`, and `query`. HTTP header fields are given
with a trailing colon, for example `content-type:` and `content-digest:`.

A leading `@` is intentionally not used, since curl treats a leading `@` in an
argument as a request to read the value from a file.

If not specified, the default set is `method authority path` (plus `query`
when a query string is present in the URL).

## Signing request headers

Header components are taken from `-H` / `--header` options only. Headers curl
adds by default (such as `User-Agent`) are not signed unless you set them
explicitly, for example:

    curl --httpsig-algo ed25519 \
      --httpsig-key k.hex \
      --httpsig-keyid mykey \
      -H "User-Agent: MyApp/1.0" \
      --httpsig-headers \
      "method authority path user-agent:" \
      $URL

Each component may appear only once. Duplicate identifiers in
`--httpsig-headers` cause curl to exit with an error (RFC 9421 Section 2).
