Long: post303
Help: Do not switch to GET after following a 303
Protocols: HTTP
See-also: post302 post301 location
Added: 7.26.0
---
Tells curl to respect RFC 7231/6.4.4 and not convert POST requests into GET
requests when following a 303 redirection. The non-RFC behaviour is ubiquitous
in web browsers, so curl does the conversion by default to maintain
consistency. However, a server may require a POST to remain a POST after such
a redirection. This option is meaningful only when using --location.
