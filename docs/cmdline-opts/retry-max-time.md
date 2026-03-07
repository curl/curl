---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: retry-max-time
Arg: <seconds>
Help: Retry only within this period
Added: 7.12.3
Category: curl timeout
Multi: single
See-also:
  - retry
  - retry-delay
Example:
  - --retry-max-time 30 --retry 10 $URL
---

# `--retry-max-time`

The retry timer is reset before the first transfer attempt. Retries are done
as usual (see --retry) as long as the timer has not reached this given limit.
Notice that if the timer has not reached the limit, the request is made and
while performing, it may take longer than this given time period. To limit a
single request's maximum time, use --max-time. Set this option to zero to not
timeout retries.

Starting in curl 8.16.0, this option accepts a time as decimal number for parts
of seconds. The decimal value needs to be provided using a dot (.) as decimal
separator - not the local version even if it might be using another separator.
