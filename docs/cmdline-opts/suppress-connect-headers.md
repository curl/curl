---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: suppress-connect-headers
Help: Suppress proxy CONNECT response headers
Category: proxy
Added: 7.54.0
Multi: boolean
See-also:
  - dump-header
  - show-headers
  - proxytunnel
Example:
  - --suppress-connect-headers --show-headers -x proxy $URL
---

# `--suppress-connect-headers`

When --proxytunnel is used and a CONNECT request is made, do not output proxy
CONNECT response headers. This option is meant to be used with --dump-header
or --show-headers which are used to show protocol headers in the output. It
has no effect on debug options such as --verbose or --trace, or any
statistics.
