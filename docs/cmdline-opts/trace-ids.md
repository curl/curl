---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: trace-ids
Help: Transfer + connection ids in verbose output
Added: 8.2.0
Category: verbose global
Multi: boolean
Scope: global
See-also:
  - trace
  - verbose
Example:
  - --trace-ids --trace-ascii output $URL
---

# `--trace-ids`

Prepend the transfer and connection identifiers to each trace or verbose line
that curl displays.
