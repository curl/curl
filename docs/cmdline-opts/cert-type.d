Long: cert-type
Protocols: TLS
Arg: <type>
Help: Certificate type (DER/PEM/ENG)
See-also: cert key key-type
Category: tls
Example: --cert-type PEM --cert file $URL
Added: 7.9.3
---
Tells curl what type the provided client certificate is using. PEM, DER, ENG
and P12 are recognized types.  If not specified, PEM is assumed.

If this option is used several times, the last one will be used.
