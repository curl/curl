Long: post302
Help: Do not switch to GET after following a 302
Protocols: HTTP
See-also: post301 post303 location
Added: 7.19.1
---
Tells curl to respect RFC 7230/6.4.2 and not convert POST requests into GET
requests when following a 302 redirection. The non-RFC behaviour is ubiquitous
in web browsers, so curl does the conversion by default to maintain
consistency. However, a server may require a POST to remain a POST after such
a redirection. This option is meaningful only when using --location.
