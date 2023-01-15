c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: header
Short: H
Arg: <header/@file>
Help: Pass custom header(s) to server
Protocols: HTTP IMAP SMTP
Category: http imap smtp
See-also: user-agent referer
Example: -H "X-First-Name: Joe" $URL
Example: -H "User-Agent: yes-please/2000" $URL
Example: -H "Host:" $URL
Added: 5.0
Multi: append
---
Extra header to include in information sent. When used within an HTTP request,
it is added to the regular request headers.

For an IMAP or SMTP MIME uploaded mail built with --form options, it is
prepended to the resulting MIME document, effectively including it at the mail
global level. It does not affect raw uploaded mails (Added in 7.56.0).

You may specify any number of extra headers. Note that if you should add a
custom header that has the same name as one of the internal ones curl would
use, your externally set header will be used instead of the internal one.
This allows you to make even trickier stuff than curl would normally do. You
should not replace internally set headers without knowing perfectly well what
you are doing. Remove an internal header by giving a replacement without
content on the right side of the colon, as in: -H "Host:". If you send the
custom header with no-value then its header must be terminated with a
semicolon, such as \-H "X-Custom-Header;" to send "X-Custom-Header:".

curl will make sure that each header you add/replace is sent with the proper
end-of-line marker, you should thus **not** add that as a part of the header
content: do not add newlines or carriage returns, they will only mess things
up for you.

This option can take an argument in @filename style, which then adds a header
for each line in the input file. Using @- will make curl read the header file
from stdin. Added in 7.55.0.

Please note that most anti-spam utilities check the presence and value of
several MIME mail headers: these are "From:", "To:", "Date:" and "Subject:"
among others and should be added with this option.

You need --proxy-header to send custom headers intended for an HTTP
proxy. Added in 7.37.0.

Passing on a "Transfer-Encoding: chunked" header when doing an HTTP request
with a request body, will make curl send the data using chunked encoding.

**WARNING**: headers set with this option will be set in all HTTP requests
- even after redirects are followed, like when told with --location. This can
lead to the header being sent to other hosts than the original host, so
sensitive headers should be used with caution combined with following
redirects.
