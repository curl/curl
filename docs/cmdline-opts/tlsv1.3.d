Long: tlsv1.3
Help: Use TLSv1.3 or greater
Protocols: TLS
Added: 7.52.0
---
Forces curl to use TLS version 1.3 or later when connecting to a remote TLS server.

Note that TLS 1.3 is only supported by a subset of TLS backends. At the time
of this writing, they are BoringSSL, NSS, and Secure Transport (on iOS 11 or
later, and macOS 10.13 or later).
