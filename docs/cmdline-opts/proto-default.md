---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proto-default
Help: Use PROTOCOL for any URL missing a scheme
Arg: <protocol>
Added: 7.45.0
Category: connection curl
Multi: single
See-also:
  - proto
  - proto-redir
Example:
  - --proto-default https ftp.example.com
---

# `--proto-default`

Use *protocol* for any provided URL missing a scheme.

An unknown or unsupported protocol causes error *CURLE_UNSUPPORTED_PROTOCOL*.

This option does not change the default proxy protocol (http).

Without this option set, curl guesses protocol based on the hostname, see
--url for details.
