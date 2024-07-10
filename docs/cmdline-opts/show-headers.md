---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: show-headers
Short: i
Help: Show response headers in output
Protocols: HTTP FTP
Category: important verbose output
Added: 4.8
Multi: boolean
See-also:
  - verbose
Example:
  - -i $URL
---

# `--show-headers`

Show response headers in the output. HTTP response headers can include things
like server name, cookies, date of the document, HTTP version and more. With
non-HTTP protocols, the "headers" are other server communication.

To view the request headers, consider the --verbose option.

Prior to 7.75.0 curl did not print the headers if --fail was used in
combination with this option and there was error reported by server.

This option was called --include before 8.10.0. The previous name remains
functional.
