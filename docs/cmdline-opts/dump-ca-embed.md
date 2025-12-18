---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: dump-ca-embed
Help: Write the embedded CA bundle to standard output
Protocols: TLS
Category: http proxy tls
Added: 8.10.0
Multi: boolean
See-also:
  - ca-native
  - cacert
  - capath
  - proxy-ca-native
  - proxy-cacert
  - proxy-capath
Example:
  - --dump-ca-embed
---

# `--dump-ca-embed`

Write the CA bundle embedded in curl to standard output, then quit.

If curl was not built with a default CA bundle embedded, the output is empty.
