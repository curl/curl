---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: ssl-no-verify-host
Help: Disable SSL host verification
Added: 8.15.0
Protocols: TLS
Category: tls
Multi: boolean
See-also:
  - insecure
  - cacert
Example:
  - --ssl-no-verify-host $URL
---

# `--ssl-no-verify-host`

This option tells curl to disable verification of Subject Name and Subject
Alternative Name.

WARNING: this option loosens the SSL security, and by using this flag you ask
for exactly that.
