---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-header
Arg: <header/@file>
Help: Pass custom header(s) to proxy
Protocols: HTTP
Added: 7.37.0
Category: proxy
Multi: append
See-also:
  - proxy
Example:
  - --proxy-header "X-First-Name: Joe" -x http://proxy $URL
  - --proxy-header "User-Agent: surprise" -x http://proxy $URL
  - --proxy-header "Host:" -x http://proxy $URL
---

# `--proxy-header`

Extra header to include in the request when sending HTTP to a proxy. You may
specify any number of extra headers. This is the equivalent option to --header
but is for proxy communication only like in CONNECT requests when you want a
separate header sent to the proxy to what is sent to the actual remote host.

curl makes sure that each header you add/replace is sent with the proper
end-of-line marker, you should thus **not** add that as a part of the header
content: do not add newlines or carriage returns, they only mess things up for
you.

Headers specified with this option are not included in requests that curl
knows are not to be sent to a proxy.

This option can take an argument in @filename style, which then adds a header
for each line in the input file (added in 7.55.0). Using @- makes curl read
the headers from stdin.

This option can be used multiple times to add/replace/remove multiple headers.
