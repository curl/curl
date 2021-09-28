Long: proto-redir
Arg: <protocols>
Help: Enable/disable PROTOCOLS on redirect
Added: 7.20.2
Category: connection curl
Example: --proto-redir =http,https $URL
---
Tells curl to limit what protocols it may use on redirect. Protocols denied by
--proto are not overridden by this option. See --proto for how protocols are
represented.

Example, allow only HTTP and HTTPS on redirect:

 curl --proto-redir -all,http,https http://example.com

By default curl will only allow HTTP, HTTPS, FTP and FTPS on redirect (since
7.65.2). Specifying *all* or *+all* enables all protocols on redirects, which
is not good for security.
