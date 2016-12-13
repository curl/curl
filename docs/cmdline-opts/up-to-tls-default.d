Long: up-to-tls-default
Tags: Versions
Protocols: SSL
Added: 7.53.0
Mutexed: up-to-tlsv1.1 up-to-tlsv1.2 up-to-tlsv1.3 ssl2 ssl3 tlsv1 tlsv1.2 tlsv1.3
Requires: TLS
See-also: http1.1 http2
Help: Use TLSv1.0 or greater
---
It is works with arguments --tlsv1.0, --tlsv1.1 which defines minimal version
of TLS. And this option defines up to recommended version(TLS1.2) of TLS that
you want to support.
