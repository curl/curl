c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: no-progress-meter
Help: Do not show the progress meter
See-also: verbose silent
Added: 7.67.0
Category: verbose
Example: --no-progress-meter -o store $URL
Multi: boolean
---
Option to switch off the progress meter output without muting or otherwise
affecting warning and informational messages like --silent does.

Note that this is the negated option name documented. You can thus use
--progress-meter to enable the progress meter again.
