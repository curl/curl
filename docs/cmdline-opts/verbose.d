c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Short: v
Long: verbose
Mutexed: trace trace-ascii
Help: Make the operation more talkative
See-also: include silent trace trace-ascii
Category: important verbose
Example: --verbose $URL
Added: 4.0
Multi: boolean
Scope: global
---
Makes curl verbose during the operation. Useful for debugging and seeing
what's going on "under the hood". A line starting with '>' means "header data"
sent by curl, '<' means "header data" received by curl that is hidden in
normal cases, and a line starting with '*' means additional info provided by
curl.

If you only want HTTP headers in the output, --include or --dump-header might
be more suitable options.

If you think this option still does not give you enough details, consider using
--trace or --trace-ascii instead.

Note that verbose output of curl activities and network traffic might contain
sensitive data, including user names, credentials or secret data content. Be
aware and be careful when sharing trace logs with others.
