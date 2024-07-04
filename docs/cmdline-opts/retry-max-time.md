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
Example:
  - --retry-max-time 30 --retry 10 $URL
---

# `--retry-max-time`

The retry timer is reset before the first transfer attempt. Retries are done
as usual (see --retry) as long as the timer has not reached this given
limit. Notice that if the timer has not reached the limit, the request is
made and while performing, it may take longer than this given time period. To
limit a single request's maximum time, use --max-time. Set this option to zero
to not timeout retries.
