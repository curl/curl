c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: max-time
Short: m
Arg: <fractional seconds>
Help: Maximum time allowed for transfer
See-also: connect-timeout retry-max-time
Category: connection
Example: --max-time 10 $URL
Example: --max-time 2.92 $URL
Added: 4.0
Multi: single
---
Maximum time in seconds that you allow each transfer to take.  This is useful
for preventing your batch jobs from hanging for hours due to slow networks or
links going down. This option accepts decimal values (added in 7.32.0).

If you enable retrying the transfer (--retry) then the maximum time counter is
reset each time the transfer is retried. You can use --retry-max-time to limit
the retry time.

The decimal value needs to provided using a dot (.) as decimal separator - not
the local version even if it might be using another separator.
