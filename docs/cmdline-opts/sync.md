---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: sync
Category: http
Added: 8.18.0
Help: Download only if local file is older
Multi: custom
See-also:
  - time-cond
Example:
  - --sync $URL
---

# `--sync`

Makes the request conditional on the remote resource being newer than the
modification time of the given local file. curl downloads the resource only if
the server reports a `Last-Modified` time that is more recent.
