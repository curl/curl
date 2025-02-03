---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Long: disable
Short: q
Help: Disable .fetchrc
Category: fetch
Added: 5.0
Multi: boolean
See-also:
  - config
Example:
  - -q $URL
---

# `--disable`

If used as the **first** parameter on the command line, the *fetchrc* config
file is not read or used. See the --config for details on the default config
file search path.
