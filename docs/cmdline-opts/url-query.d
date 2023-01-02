c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: url-query
Arg: <data>
Help: Add a URL query part
Protocols: all
See-also: data-urlencode get
Added: 7.87.0
Category: http post upload
Example: --url-query name=val $URL
Example: --url-query =encodethis http://example.net/foo
Example: --url-query name@file $URL
Example: --url-query @fileonly $URL
Example: --url-query "+name=%20foo" $URL
Multi: append
---
This option adds a piece of data, usually a name + value pair, to the end of
the URL query part. The syntax is identical to that used for --data-urlencode
with one extension:

If the argument starts with a '+' (plus), the rest of the string is provided
as-is unencoded.

The query part of a URL is the one following the question mark on the right
end.
