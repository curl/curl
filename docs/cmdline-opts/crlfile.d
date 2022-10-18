c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: crlfile
Arg: <file>
Protocols: TLS
Help: Use this CRL list
Added: 7.19.7
Category: tls
Example: --crlfile rejects.txt $URL
See-also: cacert capath
Multi: single
---
Provide a file using PEM format with a Certificate Revocation List that may
specify peer certificates that are to be considered revoked.
