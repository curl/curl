Long: tls-max
Arg: <VERSION>
Tags: Versions
Protocols: SSL
Added: 7.54.0
Requires: TLS
See-also: tlsv1.0 tlsv1.1 tlsv1.2 tlsv1.3
Help: Set maximum allowed TLS version
---
VERSION defines maximum supported TLS version. The minimum acceptable version
is set by tlsv1.0, tlsv1.1, tlsv1.2 or tlsv1.3.

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
