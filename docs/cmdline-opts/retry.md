---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: retry
Arg: <num>
Added: 7.12.3
Help: Retry request if transient problems occur
Category: curl
Multi: single
See-also:
  - retry-max-time
Example:
  - --retry 7 $URL
---

# `--retry`

If a transient error is returned when curl tries to perform a transfer, it
retries this number of times before giving up. Setting the number to 0
makes curl do no retries (which is the default). Transient error means either:
a timeout, an FTP 4xx response code or an HTTP 408, 429, 500, 502, 503 or 504
response code.

When curl is about to retry a transfer, it first waits one second and then for
all forthcoming retries it doubles the waiting time until it reaches 10
minutes, which then remains the set fixed delay time between the rest of the
retries. By using --retry-delay you disable this exponential backoff algorithm.
See also --retry-max-time to limit the total time allowed for retries.

curl complies with the Retry-After: response header if one was present to know
when to issue the next retry (added in 7.66.0).
