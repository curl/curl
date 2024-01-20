---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: globoff
Short: g
Help: Disable URL sequences and ranges using {} and []
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

This option switches off the "URL globbing parser". When you set this option,
you can specify URLs that contain the letters {}[] without having curl itself
interpret them. Note that these letters are not normal legal URL contents but
they should be encoded according to the URI standard.
