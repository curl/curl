---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: form-escape
Help: Escape form fields using backslash
Protocols: HTTP imap smtp
Added: 7.81.0
Category: http upload post
Multi: single
See-also:
  - form
Example:
  - --form-escape -F 'field\name=curl' -F 'file=@load"this' $URL
---

# `--form-escape`

Pass on names of multipart form fields and files using backslash-escaping
instead of percent-encoding.
