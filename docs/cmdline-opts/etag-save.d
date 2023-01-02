c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: etag-save
Arg: <file>
Help: Parse ETag from a request and save it to a file
Protocols: HTTP
Added: 7.68.0
Category: http
Example: --etag-save storetag.txt $URL
See-also: etag-compare
Multi: single
---
This option saves an HTTP ETag to the specified file. An ETag is a
caching related header, usually returned in a response.

If no ETag is sent by the server, an empty file is created.
