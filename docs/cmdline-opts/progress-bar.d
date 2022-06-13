c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Short: #
Long: progress-bar
Help: Display transfer progress as a bar
Category: verbose
Example: -# -O $URL
Added: 5.10
See-also: styled-output
---
Make curl display transfer progress as a simple progress bar instead of the
standard, more informational, meter.

This progress bar draws a single line of '#' characters across the screen and
shows a percentage if the transfer size is known. For transfers without a
known size, there will be space ship (-=o=-) that moves back and forth but
only while data is being transferred, with a set of flying hash sign symbols on
top.

This option is global and does not need to be specified for each use of
--next.
