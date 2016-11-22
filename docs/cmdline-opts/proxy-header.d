Long: proxy-header
Arg: <header>
Help: Pass custom header LINE to proxy
Protocols: HTTP
Added: 7.37.0
---
Extra header to include in the request when sending HTTP to a proxy. You may
specify any number of extra headers. This is the equivalent option to --header
but is for proxy communication only like in CONNECT requests when you want a
separate header sent to the proxy to what is sent to the actual remote host.

curl will make sure that each header you add/replace is sent with the proper
end-of-line marker, you should thus \fBnot\fP add that as a part of the header
content: do not add newlines or carriage returns, they will only mess things
up for you.

Headers specified with this option will not be included in requests that curl
knows will not be sent to a proxy.

This option can be used multiple times to add/replace/remove multiple headers.
