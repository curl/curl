c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: no-buffer
Short: N
Help: Disable buffering of the output stream
Category: curl
Example: --no-buffer $URL
Added: 6.5
See-also: progress-bar
Multi: boolean
---
Disables the buffering of the output stream. In normal work situations, curl
will use a standard buffered output stream that will have the effect that it
will output the data in chunks, not necessarily exactly when the data arrives.
Using this option will disable that buffering.
