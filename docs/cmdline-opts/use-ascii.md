---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Short: B
Long: use-ascii
Help: Use ASCII/text transfer
Protocols: FTP LDAP
Category: ftp output ldap
Added: 5.0
Multi: boolean
See-also:
  - crlf
  - data-ascii
Example:
  - -B ftp://example.com/README
---

# `--use-ascii`

Enable ASCII transfer mode. For FTP, this can also be enforced by using a URL
that ends with `;type=A`. This option causes data sent to stdout to be in text
mode for Win32 systems.
