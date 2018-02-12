Long: socks5-gssapi-nec
Help: Compatibility with NEC SOCKS5 server
Added: 7.19.4
---
As part of the GSS-API negotiation a protection mode is negotiated. RFC 1961
says in section 4.3/4.4 it should be protected, but the NEC reference
implementation does not.  The option --socks5-gssapi-nec allows the
unprotected exchange of the protection mode negotiation.
