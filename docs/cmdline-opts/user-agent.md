---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Short: A
Long: user-agent
Arg: <name>
Help: Send User-Agent <name> to server
Protocols: HTTP
Category: important http common
Added: 4.5.1
Multi: single
See-also:
  - header
  - proxy-header
Example:
  - -A "Agent 007" $URL
---

# `--user-agent`

Specify the User-Agent string to send to the HTTP server. To encode blanks in
the string, surround the string with single quote marks. This header can also
be set with the --header or the --proxy-header options.

If you give an empty argument to --user-agent (""), it removes the header
completely from the request. If you prefer a blank header, you can set it to a
single space (" ").

By default, curl uses curl/VERSION, such as User-Agent: curl/`%VERSION`.
