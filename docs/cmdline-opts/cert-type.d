Long: cert-type
Protocols: TLS
Arg: <type>
Help: Certificate type (DER/PEM/ENG)
See-also: cert key key-type
---
Tells curl what type the provided client certificate is using. PEM, DER, ENG
and P12 are recognized types.  If not specified, PEM is assumed.

If this option is used several times, the last one will be used.
