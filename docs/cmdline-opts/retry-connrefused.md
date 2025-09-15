---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: retry-connrefused
Help: Retry on connection refused (with --retry)
Added: 7.52.0
Category: curl
Multi: boolean
See-also:
  - retry
  - retry-all-errors
Example:
  - --retry-connrefused --retry 7 $URL
---

# `--retry-connrefused`

In addition to the other conditions, also consider ECONNREFUSED as a transient
error for --retry. This option is used together with --retry. Normally, a
confused connection is not considered a transient error and therefore thus not
otherwise trigger a retry.
