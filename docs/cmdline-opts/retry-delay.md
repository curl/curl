---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: retry-delay
Arg: <seconds>
Help: Wait time between retries
Added: 7.12.3
Category: curl timeout
Multi: single
See-also:
  - retry
  - retry-max-time
Example:
  - --retry-delay 5 --retry 7 $URL
---

# `--retry-delay`

Make curl sleep this amount of time before each retry when a transfer has
failed with a transient error (it changes the default backoff time algorithm
between retries). This option is only interesting if --retry is also
used. Setting this delay to zero makes curl use the default backoff time.

By default, curl uses an exponentially increasing timeout between retries.

Starting in curl 8.16.0, this option accepts a time as decimal number for parts
of seconds. The decimal value needs to be provided using a dot (.) as decimal
separator - not the local version even if it might be using another separator.
