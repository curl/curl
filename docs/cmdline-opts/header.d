Long: header
Short: H
Arg: <header/@file>
Help: Pass custom header(s) to server
Protocols: HTTP
Category: http
See-also: user-agent referer
---
Extra header to include in the request when sending HTTP to a server. You may
specify any number of extra headers. Note that if you should add a custom
header that has the same name as one of the internal ones curl would use, your
externally set header will be used instead of the internal one. This allows
you to make even trickier stuff than curl would normally do. You should not
replace internally set headers without knowing perfectly well what you're
doing. Remove an internal header by giving a replacement without content on
the right side of the colon, as in: -H \&"Host:". If you send the custom
header with no-value then its header must be terminated with a semicolon, such
as \-H \&"X-Custom-Header;" to send "X-Custom-Header:".

curl will make sure that each header you add/replace is sent with the proper
end-of-line marker, you should thus \fBnot\fP add that as a part of the header
content: do not add newlines or carriage returns, they will only mess things
up for you.

This option can take an argument in @filename style, which then adds a header
for each line in the input file. Using @- will make curl read the header file
from stdin. Added in 7.55.0.

You need --proxy-header to send custom headers intended for a HTTP
proxy. Added in 7.37.0.

Passing on a "Transfer-Encoding: chunked" header when doing a HTTP request
with a requst body, will make curl send the data using chunked encoding.

Example:

 curl -H "X-First-Name: Joe" http://example.com/

\fBWARNING\fP: headers set with this option will be set in all requests - even
after redirects are followed, like when told with --location. This can lead to
the header being sent to other hosts than the original host, so sensitive
headers should be used with caution combined with following redirects.

This option can be used multiple times to add/replace/remove multiple headers.
