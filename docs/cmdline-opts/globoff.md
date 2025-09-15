---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: globoff
Short: g
Help: Disable URL globbing with {} and []
Category: curl
Added: 7.6
Multi: boolean
See-also:
  - config
  - disable
Example:
  - -g "https://example.com/{[]}}}}"
---

# `--globoff`

Switch off the URL globbing function. When you set this option, you can
specify URLs that contain the letters {}[] without having curl itself
interpret them. Note that these letters are not normal legal URL contents but
they should be encoded according to the URI standard.

curl detects numerical IPv6 addresses when used in URLs and excludes them from
the treatment, so they can still be used without having to disable globbing.
