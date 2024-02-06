---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: get
Short: G
Help: Put the post data in the URL and use GET
Protocols: HTTP
Category: http upload
Added: 7.8.1
Multi: boolean
See-also:
  - data
  - request
Example:
  - --get $URL
  - --get -d "tool=curl" -d "age=old" $URL
  - --get -I -d "tool=curl" $URL
---

# `--get`

When used, this option makes all data specified with --data, --data-binary
or --data-urlencode to be used in an HTTP GET request instead of the POST
request that otherwise would be used. The data is appended to the URL
with a '?' separator.

If used in combination with --head, the POST data is instead appended to the
URL with a HEAD request.
