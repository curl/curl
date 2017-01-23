Long: tls-max
Arg: <VERSION>
Tags: Versions
Protocols: SSL
Added: 7.53.0
Requires: TLS
See-also: tlsv1.0 tlsv1.1 tlsv1.2
Help: Use TLSv1.0 or greater
---
Defines a range of supported TLS versions up to VERSION. A minimum is defined
by arguments tlsv1.0 or tlsv1.1 or tlsv1.2.

.RS
.IP "default"
Use up to recommended TLS version.
.IP "1.0"
Use up to TLSv1.0.
.IP "1.1"
Use up to TLSv1.1.
.IP "1.2"
Use up to TLSv1.2.
.IP "1.3"
Use up to TLSv1.3.
.RE
