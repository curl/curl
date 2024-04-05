---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: etag-save
Arg: <file>
Help: Parse incoming ETag and save to a file
Protocols: HTTP
Added: 7.68.0
Category: http
Multi: single
See-also:
  - etag-compare
Example:
  - --etag-save storetag.txt $URL
---

# `--etag-save`

Save an HTTP ETag to the specified file. An ETag is a caching related header,
usually returned in a response.

If no ETag is sent by the server, an empty file is created.
