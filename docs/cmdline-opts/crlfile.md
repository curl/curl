---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: crlfile
Arg: <file>
Protocols: TLS
Help: Certificate Revocation list
Added: 7.19.7
Category: tls
Multi: single
See-also:
  - cacert
  - capath
Example:
  - --crlfile rejects.txt $URL
---

# `--crlfile`

Provide a file using PEM format with a Certificate Revocation List that may
specify peer certificates that are to be considered revoked.
