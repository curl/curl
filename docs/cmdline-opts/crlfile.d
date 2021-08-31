Long: crlfile
Arg: <file>
Protocols: TLS
Help: Use this CRL list
Added: 7.19.7
Category: tls
Example: --crlfile rejects.txt $URL
---
Provide a file using PEM format with a Certificate Revocation List that may
specify peer certificates that are to be considered revoked.

If this option is used several times, the last one will be used.
