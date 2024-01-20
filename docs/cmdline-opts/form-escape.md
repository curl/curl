---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: form-escape
Help: Escape multipart form field/file names using backslash
Protocols: HTTP
Added: 7.81.0
Category: http upload
Multi: single
See-also:
  - form
Example:
  - --form-escape -F 'field\name=curl' -F 'file=@load"this' $URL
---

# `--form-escape`

Tells curl to pass on names of multipart form fields and files using
backslash-escaping instead of percent-encoding.
