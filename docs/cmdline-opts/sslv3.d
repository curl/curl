Short: 3
Long: sslv3
Tags: Versions
Protocols: SSL
Added:
Mutexed: sslv2 tlsv1 tlsv1.1 tlsv1.2
Requires: TLS
See-also: http1.1 http2
Help: Use SSLv3
Category: tls
---
Forces curl to use SSL version 3 when negotiating with a remote SSL
server. Sometimes curl is built without SSLv3 support. SSLv3 is widely
considered insecure (see RFC 7568).
