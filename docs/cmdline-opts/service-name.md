---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: service-name
Help: SPNEGO service name
Arg: <name>
Added: 7.43.0
Category: misc
Multi: single
See-also:
  - negotiate
  - proxy-service-name
Example:
  - --service-name sockd/server $URL
---

# `--service-name`

Set the service name for SPNEGO.
