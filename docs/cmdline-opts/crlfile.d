Long: crlfile
Arg: <file>
Protocols: TLS
Help: Get a CRL list in PEM format from the given file
Added: 7.19.7
Category: tls
---
Provide a file using PEM format with a Certificate Revocation List that may
specify peer certificates that are to be considered revoked.

If this option is used several times, the last one will be used.
