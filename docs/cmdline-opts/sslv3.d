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
Example: --sslv3 $URL
---
This option previously asked curl to use SSLv3, but starting in curl 7.77.0
this instruction is ignored. SSLv3 is widely considered insecure (see RFC
7568).
