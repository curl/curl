c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: get
Short: G
Help: Put the post data in the URL and use GET
Category: http upload
Example: --get $URL
Example: --get -d "tool=curl" -d "age=old" $URL
Example: --get -I -d "tool=curl" $URL
Added: 7.8.1
See-also: data request
Multi: boolean
---
When used, this option makes all data specified with --data, --data-binary
or --data-urlencode to be used in an HTTP GET request instead of the POST
request that otherwise would be used. The data is appended to the URL
with a '?' separator.

If used in combination with --head, the POST data is instead appended to the
URL with a HEAD request.
