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
  - dump-header
Example:
  - -i $URL
---

# `--show-headers`

Show response headers in the output. HTTP response headers can include things
like server name, cookies, date of the document, HTTP version and more. With
non-HTTP protocols, the "headers" are other server communication.

This option makes the response headers get saved in the same stream/output as
the data. --dump-header exists to save headers in a separate stream.

When HTTP headers is output to a tty, curl may use escape codes to make the
header field names appear as bold and URLs in `Location:` headers to be
especially marked as such. Disable the use of terminal escape codes with
--no-styled-output.

To view the request headers, consider the --verbose option.

Prior to 7.75.0 curl did not print the headers if --fail was used in
combination with this option and there was an error reported by the server.

This option was called --include before 8.10.0. The previous name remains
functional.
