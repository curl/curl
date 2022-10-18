c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-header
Arg: <header/@file>
Help: Pass custom header(s) to proxy
Protocols: HTTP
Added: 7.37.0
Category: proxy
Example: --proxy-header "X-First-Name: Joe" -x http://proxy $URL
Example: --proxy-header "User-Agent: surprise" -x http://proxy $URL
Example: --proxy-header "Host:" -x http://proxy $URL
See-also: proxy
Multi: append
---
Extra header to include in the request when sending HTTP to a proxy. You may
specify any number of extra headers. This is the equivalent option to --header
but is for proxy communication only like in CONNECT requests when you want a
separate header sent to the proxy to what is sent to the actual remote host.

curl will make sure that each header you add/replace is sent with the proper
end-of-line marker, you should thus **not** add that as a part of the header
content: do not add newlines or carriage returns, they will only mess things
up for you.

Headers specified with this option will not be included in requests that curl
knows will not be sent to a proxy.

Starting in 7.55.0, this option can take an argument in @filename style, which
then adds a header for each line in the input file. Using @- will make curl
read the header file from stdin.

This option can be used multiple times to add/replace/remove multiple headers.
