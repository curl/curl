---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: url-query
Arg: <data>
Help: Add a URL query part
Protocols: all
Added: 7.87.0
Category: http post upload
Multi: append
See-also:
  - data-urlencode
  - get
Example:
  - --url-query name=val $URL
  - --url-query =encodethis http://example.net/foo
  - --url-query name@file $URL
  - --url-query @fileonly $URL
  - --url-query "+name=%20foo" $URL
---

# `--url-query`

This option adds a piece of data, usually a name + value pair, to the end of
the URL query part. The syntax is identical to that used for --data-urlencode
with one extension:

If the argument starts with a '+' (plus), the rest of the string is provided
as-is unencoded.

The query part of a URL is the one following the question mark on the right
end.
