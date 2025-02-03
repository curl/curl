---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Long: get
Short: G
Help: Put the post data in the URL and use GET
Protocols: HTTP
Category: http
Added: 7.8.1
Multi: boolean
See-also:
  - data
  - request
Example:
  - --get $URL
  - --get -d "tool=fetch" -d "age=old" $URL
  - --get -I -d "tool=fetch" $URL
---

# `--get`

When used, this option makes all data specified with --data, --data-binary or
--data-urlencode to be used in an HTTP GET request instead of the POST request
that otherwise would be used. fetch appends the provided data to the URL as a
query string.

If used in combination with --head, the POST data is instead appended to the
URL with a HEAD request.
