Long: cert-type
Protocols: TLS
Arg: <type>
Help: Certificate file type (DER/PEM/ENG)
See-also: cert key key-type
---
Tells curl what certificate type the provided certificate is in. PEM, DER and
ENG are recognized types.  If not specified, PEM is assumed.

If this option is used several times, the last one will be used.
