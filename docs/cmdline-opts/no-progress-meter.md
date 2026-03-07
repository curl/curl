---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: no-progress-meter
Help: Do not show the progress meter
Added: 7.67.0
Category: verbose
Multi: boolean
See-also:
  - verbose
  - silent
Example:
  - --no-progress-meter -o store $URL
---

# `--no-progress-meter`

Option to switch off the progress meter output without muting or otherwise
affecting warning and informational messages like --silent does.

Note that this is the negated option name documented. You can thus use
--progress-meter to enable the progress meter again.
