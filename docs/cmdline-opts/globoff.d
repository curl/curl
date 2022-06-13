c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: globoff
Short: g
Help: Disable URL sequences and ranges using {} and []
Category: curl
Example: -g "https://example.com/{[]}}}}"
Added: 7.6
See-also: config disable
---
This option switches off the "URL globbing parser". When you set this option,
you can specify URLs that contain the letters {}[] without having curl itself
interpret them. Note that these letters are not normal legal URL contents but
they should be encoded according to the URI standard.
