---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-crlfile
Arg: <file>
Help: Set a CRL list for proxy
Added: 7.52.0
Category: proxy tls
Multi: single
See-also:
  - crlfile
  - proxy
Example:
  - --proxy-crlfile rejects.txt -x https://proxy $URL
---

# `--proxy-crlfile`

Provide filename for a PEM formatted file with a Certificate Revocation List
that specifies peer certificates that are considered revoked when
communicating with an HTTPS proxy.

Equivalent to --crlfile but only used in HTTPS proxy context.
