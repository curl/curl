---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: krb
Arg: <level>
Help: Enable Kerberos with security <level>
Protocols: FTP
Requires: Kerberos
Category: deprecated
Added: 7.3
Multi: single
See-also:
  - delegation
  - ssl
Example:
  - --krb clear ftp://example.com/
---

# `--krb`

Deprecated option (added in 8.17.0). It has no function anymore.

Enable Kerberos authentication and use. The level must be entered and should
be one of `clear`, `safe`, `confidential`, or `private`. Should you use a
level that is not one of these, `private` is used.
