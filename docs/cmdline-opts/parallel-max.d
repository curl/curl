c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: parallel-max
Arg: <num>
Help: Maximum concurrency for parallel transfers
Added: 7.66.0
See-also: parallel
Category: connection curl
Example: --parallel-max 100 -Z $URL ftp://example.com/
Multi: single
---
When asked to do parallel transfers, using --parallel, this option controls
the maximum amount of transfers to do simultaneously.

This option is global and does not need to be specified for each use of
--next.

The default is 50.
