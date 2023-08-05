c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: etag-compare
Arg: <file>
Help: Pass an ETag from a file as a custom header
Protocols: HTTP
Added: 7.68.0
Category: http
Example: --etag-compare etag.txt $URL
See-also: etag-save time-cond
Multi: single
---
This option makes a conditional HTTP request for the specific ETag read
from the given file by sending a custom If-None-Match header using the
stored ETag.

For correct results, make sure that the specified file contains only a
single line with the desired ETag. An empty file is parsed as an empty
ETag.

Use the option --etag-save to first save the ETag from a response, and
then use this option to compare against the saved ETag in a subsequent
request.
