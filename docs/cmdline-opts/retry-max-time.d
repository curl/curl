c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: retry-max-time
Arg: <seconds>
Help: Retry only within this period
Added: 7.12.3
Category: curl
Example: --retry-max-time 30 --retry 10 $URL
See-also: retry
Multi: single
---
The retry timer is reset before the first transfer attempt. Retries will be
done as usual (see --retry) as long as the timer has not reached this given
limit. Notice that if the timer has not reached the limit, the request will be
made and while performing, it may take longer than this given time period. To
limit a single request's maximum time, use --max-time. Set this option to
zero to not timeout retries.
