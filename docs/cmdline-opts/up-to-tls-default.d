Long: up-to-tls-default
Tags: Versions
Protocols: SSL
Added: 7.53.0
Mutexed: up-to-tlsv1.1 up-to-tlsv1.2 up-to-tlsv1.3
Requires: TLS
See-also: tlsv1.0 tlsv1.1
Help: Use TLSv1.0 or greater
---
Use TLS up to recommended TLS version.

It defines a range of supported TLS versions. The minimum must be defined by
tlsv1.0 or tlsv1.1 and the maximum is defined by this argument.
