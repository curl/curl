---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: data-raw
Arg: <data>
Protocols: HTTP
Help: HTTP POST data, '@' allowed
Added: 7.43.0
Category: http post upload
Multi: append
See-also:
  - data
Example:
  - --data-raw "hello" $URL
  - --data-raw "@at@at@" $URL
---

# `--data-raw`

Post data similarly to --data but without the special interpretation of the @
character.
