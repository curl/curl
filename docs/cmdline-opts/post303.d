Long: post303
Help: Do not switch to GET after following a 303
Protocols: HTTP
See-also: post302 post301 location
Added: 7.26.0
Category: http post
Example: --post303 --location -d "data" $URL
---
Tells curl to violate RFC 7231/6.4.4 and not convert POST requests into GET
requests when following 303 redirections. A server may require a POST to
remain a POST after a 303 redirection. This option is meaningful only when
using --location.
