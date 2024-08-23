---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Short: #
Long: progress-bar
Help: Display transfer progress as a bar
Category: verbose global
Added: 5.10
Multi: boolean
Scope: global
See-also:
  - styled-output
Example:
  - -# -O $URL
---

# `--progress-bar`

Make curl display transfer progress as a simple progress bar instead of the
standard, more informational, meter.

This progress bar draws a single line of '#' characters across the screen and
shows a percentage if the transfer size is known. For transfers without a
known size, there is a space ship (-=o=-) that moves back and forth but only
while data is being transferred, with a set of flying hash sign symbols on
top.
