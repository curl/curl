---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Short: c
Long: cookie-jar
Arg: <filename>
Protocols: HTTP
Help: Save cookies to <filename> after operation
Category: http
Added: 7.9
Multi: single
See-also:
  - cookie
  - junk-session-cookies
Example:
  - -c store-here.txt $URL
  - -c store-here.txt -b read-these $URL
---

# `--cookie-jar`

Specify to which file you want curl to write all cookies after a completed
operation. Curl writes all cookies from its in-memory cookie storage to the
given file at the end of operations. Even if no cookies are known, a file is
created so that it removes any formerly existing cookies from the file. The
file uses the Netscape cookie file format. If you set the filename to a single
minus, "-", the cookies are written to stdout.

The file specified with --cookie-jar is only used for output. No cookies are
read from the file. To read cookies, use the --cookie option. Both options
can specify the same file.

This command line option activates the cookie engine that makes curl record
and use cookies. The --cookie option also activates it.

If the cookie jar cannot be created or written to, the whole curl operation
does not fail or even report an error clearly. Using --verbose gets a warning
displayed, but that is the only visible feedback you get about this possibly
lethal situation.
