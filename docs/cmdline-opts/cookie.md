---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Short: b
Long: cookie
Arg: <data|filename>
Protocols: HTTP
Help: Send cookies from string/load from file
Category: http common
Added: 4.9
Multi: append
See-also:
  - cookie-jar
  - junk-session-cookies
Example:
  - -b "" $URL
  - -b cookiefile $URL
  - -b cookiefile -c cookiefile $URL
  - -b name=Jane $URL
---

# `--cookie`

This option has two slightly separate cookie sending functions.

Either: pass the exact data to send to the HTTP server in the Cookie header.
It is supposedly data previously received from the server in a `Set-Cookie:`
line. The data should be in the format `NAME1=VALUE1; NAME2=VALUE2`. When
given a set of specific cookies, curl populates its cookie header with this
content explicitly in all outgoing request(s). If multiple requests are done
due to authentication, followed redirects or similar, they all get this cookie
header passed on.

Or: If no `=` symbol is used in the argument, it is instead treated as a
filename to read previously stored cookie from. This option also activates the
cookie engine which makes curl record incoming cookies, which may be handy if
you are using this in combination with the --location option or do multiple
URL transfers on the same invoke.

If the filename is a single minus ("-"), curl reads the contents from stdin.
If the filename is an empty string ("") and is the only cookie input, curl
activates the cookie engine without any cookies.

The file format of the file to read cookies from should be plain HTTP headers
(Set-Cookie style) or the Netscape/Mozilla cookie file format.

The file specified with --cookie is only used as input. No cookies are written
to that file. To store cookies, use the --cookie-jar option.

If you use the Set-Cookie file format and do not specify a domain then the
cookie is not sent since the domain never matches. To address this, set a
domain in Set-Cookie line (doing that includes subdomains) or preferably: use
the Netscape format.

Users often want to both read cookies from a file and write updated cookies
back to a file, so using both --cookie and --cookie-jar in the same command
line is common.

If curl is built with PSL (**Public Suffix List**) support, it detects and
discards cookies that are specified for such suffix domains that should not be
allowed to have cookies. If curl is *not* built with PSL support, it has no
ability to stop super cookies.
