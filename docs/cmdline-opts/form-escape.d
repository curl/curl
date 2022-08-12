c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: form-escape
Help: Escape multipart form field/file names using backslash
Protocols: HTTP
See-also: form
Added: 7.81.0
Category: http upload
Example: --form-escape -F 'field\\name=curl' -F 'file=@load"this' $URL
---
Tells curl to pass on names of multipart form fields and files using
backslash-escaping instead of percent-encoding.
