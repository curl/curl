---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: proxy-cacert
Help: CA certificates to verify proxy against
Arg: <file>
Added: 7.52.0
Category: proxy tls
Multi: single
See-also:
  - proxy-capath
  - cacert
  - capath
  - proxy
Example:
  - --proxy-cacert CA-file.txt -x https://proxy $URL
---

# `--proxy-cacert`

Use the specified certificate file to verify the HTTPS proxy. The file may
contain multiple CA certificates. The certificate(s) must be in PEM format.

This allows you to use a different trust for the proxy compared to the remote
server connected to via the proxy.

Equivalent to --cacert but used in HTTPS proxy context.
