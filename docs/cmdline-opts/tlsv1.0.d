Long: tlsv1.0
Help: Use TLSv1.0 or greater
Protocols: TLS
Added: 7.34.0
Category: tls
Example: --tlsv1.0 $URL
---
Forces curl to use TLS version 1.0 or later when connecting to a remote TLS server.

In old versions of curl this option was documented to allow _only_ TLS 1.0,
but behavior was inconsistent depending on the TLS library. Use --tls-max if
you want to set a maximum TLS version.
