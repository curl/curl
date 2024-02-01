---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: retry-delay
Arg: <seconds>
Help: Wait time between retries
Added: 7.12.3
Category: curl
Multi: single
See-also:
  - retry
  - retry-ignore-server-time
Example:
  - --retry-delay 5 --retry 7 $URL
---

# `--retry-delay`

Make curl sleep this amount of time before each retry when a transfer has
failed with a transient error (it changes the default backoff time algorithm
between retries). This option is only interesting if --retry is also
used. Setting this delay to zero makes curl use the default backoff time.

For HTTP transient errors (see --retry) the server can override curl's retry
delay time by setting the Retry-After response header (added in 7.66.0). You
can ignore the server's requested Retry-After time by using
--retry-ignore-server-time but it is not polite to do so (added in 8.7.0).
