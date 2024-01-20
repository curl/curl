---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: curves
Arg: <algorithm list>
Help: (EC) TLS key exchange algorithm(s) to request
Protocols: TLS
Added: 7.73.0
Category: tls
Multi: single
See-also:
  - ciphers
Example:
  - --curves X25519 $URL
---

# `--curves`

Tells curl to request specific curves to use during SSL session establishment
according to RFC 8422, 5.1. Multiple algorithms can be provided by separating
them with `:` (e.g. `X25519:P-521`). The parameter is available identically in
the OpenSSL `s_client` and `s_server` utilities.

--curves allows a OpenSSL powered curl to make SSL-connections with exactly
the (EC) curve requested by the client, avoiding nontransparent client/server
negotiations.

If this option is set, the default curves list built into OpenSSL are ignored.
