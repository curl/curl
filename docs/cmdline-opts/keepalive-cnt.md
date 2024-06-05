---
c: Copyright (C) Daniel Stenberg, <daniel.se>, et al.
SPDX-License-Identifier: curl
Long: keepalive-cnt
Arg: <integer>
Help: Maximum number of keepalive probes
Added: 8.9.0
Category: connection
Multi: single
See-also:
  - keepalive-time
  - no-keepalive
Example:
  - --keepalive-cnt 3 $URL
---

# `--keepalive-cnt`

Set the maximum number of keepalive probes TCP should send but get no response
before dropping the connection. This option is usually used in conjunction
with --keepalive-time.

This option is supported on Linux, *BSD/macOS, Windows \>=10.0.16299, Solaris
11.4, and recent AIX, HP-UX and more. This option has no effect if
--no-keepalive is used.

If unspecified, the option defaults to 9.
