Short: 1
Long: tlsv1
Tags: Versions
Protocols: SSL
Added:
Mutexed: tlsv1.1 tlsv1.2
Requires: TLS
See-also: http1.1 http2
Help: Use TLSv1.0 or greater
---
Forces curl to use TLS version 1.x when negotiating with a remote TLS server.
You can use options --tlsv1.0, --tlsv1.1, --tlsv1.2, and --tlsv1.3 to control
the TLS version more precisely (if the SSL backend in use supports such a
level of control).
