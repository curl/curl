---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: head
Short: I
Help: Show document info only
Protocols: HTTP FTP FILE
Category: http ftp file
Added: 4.0
Multi: boolean
See-also:
  - get
  - verbose
  - trace-ascii
Example:
  - -I $URL
---

# `--head`

Fetch the headers only. HTTP-servers feature the command HEAD which this uses
to get nothing but the header of a document. When used on an FTP or FILE URL,
curl displays the file size and last modification time only.
