---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: url-encode
Help: URL-encode the URL
Added: 8.23.1
Category: curl
Multi: boolean
See-also:
  - url
  - url-query
  - path-as-is
Example:
  - --url-encode "https://example.com/a b?q=hello world"
---

# `--url-encode`

URL-encode the given URL before it is used.

Spaces in the path and fragment are encoded as `%20`, spaces in the query are
encoded as `+`, and bytes that cannot appear literally in a URL are encoded as
`%XX`. Bytes that are already percent-encoded are left as-is.

This makes it possible to pass URLs containing spaces or other characters that
otherwise are rejected as malformed.
