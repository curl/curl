---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: junk-session-cookies
Short: j
Help: Ignore session cookies read from file
Protocols: HTTP
Category: http
Added: 7.9.7
Multi: boolean
See-also:
  - cookie
  - cookie-jar
Example:
  - --junk-session-cookies -b cookies.txt $URL
---

# `--junk-session-cookies`

When curl is told to read cookies from a given file, this option makes it
discard all "session cookies". This has the same effect as if a new session is
started. Typical browsers discard session cookies when they are closed down.
