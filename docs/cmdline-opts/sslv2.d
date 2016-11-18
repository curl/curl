Short: 2
Long: sslv2
Tags: Versions
Protocols: SSL
Added:
Mutexed: sslv3 tlsv1 tlsv1.1 tlsv1.2
Requires: TLS
See-also: http1.1 http2
Help: Use SSLv2
---
Forces curl to use SSL version 2 when negotiating with a remote SSL
server. Sometimes curl is built without SSLv2 support. SSLv2 is widely
considered insecure (see RFC 6176).
