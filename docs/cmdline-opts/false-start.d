Long: false-start
Help: Enable TLS False Start
Protocols: TLS
Added: 7.42.0
Category: tls
---
Tells curl to use false start during the TLS handshake. False start is a mode
where a TLS client will start sending application data before verifying the
server's Finished message, thus saving a round trip when performing a full
handshake.

This is currently only implemented in the NSS and Secure Transport (on iOS 7.0
or later, or OS X 10.9 or later) backends.
