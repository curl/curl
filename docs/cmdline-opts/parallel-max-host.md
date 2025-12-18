---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: parallel-max-host
Arg: <num>
Help: Maximum connections to a single host
Added: 8.16.0
Category: connection curl global
Multi: single
Scope: global
See-also:
  - parallel
  - parallel-max
Example:
  - --parallel-max-host 5 -Z $URL ftp://example.com/
---

# `--parallel-max-host`

When asked to do parallel transfers, using --parallel, this option controls
the maximum amount of concurrent connections curl is allowed to do to the same
protocol + hostname + port number target.

The limit is enforced by libcurl and queued "internally", which means that
transfers that are waiting for an available connection still look like started
transfers in the progress meter.

The default is 0 (unlimited). 65535 is the largest supported value.
