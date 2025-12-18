---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: tcp-nodelay
Help: Set TCP_NODELAY
Added: 7.11.2
Category: connection
Multi: boolean
See-also:
  - no-buffer
Example:
  - --tcp-nodelay $URL
---

# `--tcp-nodelay`

Turn on the TCP_NODELAY option.

This option disables the Nagle algorithm on TCP connections. The purpose of
this algorithm is to minimize the number of small packets on the network
(where "small packets" means TCP segments less than the Maximum Segment Size
for the network).

Maximizing the amount of data sent per TCP segment is good because it
amortizes the overhead of the send. However, in some cases small segments may
need to be sent without delay. This is less efficient than sending larger
amounts of data at a time, and can contribute to congestion on the network if
overdone.

curl sets this option by default and you need to explicitly switch it off if
you do not want it on (added in 7.50.2).
