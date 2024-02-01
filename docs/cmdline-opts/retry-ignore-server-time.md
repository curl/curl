---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: retry-ignore-server-time
Help: Ignore the server's retry delay time (use with --retry)
Added: 8.7.0
Category: curl
Multi: boolean
See-also:
  - retry
  - retry-delay
Example:
  - --retry 5 --retry-ignore-server-time $URL
---

# `--retry-ignore-server-time`

Ignore the server's retry delay time (aka Retry-After response header). This
option is used together with --retry.

Normally curl complies with the standard that allows the server to set the
retry delay time before retrying a transient HTTP error (see --retry). When
that happens the server delay time overrides curl's delay time. This option
effectively stops the server from doing that.

A real-world scenario where you may need to use this option is a heavily
overloaded server sets a retry time that is too short and you want to make sure
that the retry delay you set (or the default algorithmic retry delay) is used
instead because it gives a better chance of success.

There's really no polite compliant use of this option so it should be used on
a case-by-case basis and is not recommended for your curlrc configuration file.
