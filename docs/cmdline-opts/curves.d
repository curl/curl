c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: curves
Arg: <algorithm list>
Help: (EC) TLS key exchange algorithm(s) to request
Protocols: TLS
Added: 7.73.0
Category: tls
Example: --curves X25519 $URL
See-also: ciphers
Multi: single
---
Tells curl to request specific curves to use during SSL session establishment
according to RFC 8422, 5.1.  Multiple algorithms can be provided by separating
them with ":" (e.g.  "X25519:P-521").  The parameter is available identically
in the "openssl s_client/s_server" utilities.

--curves allows a OpenSSL powered curl to make SSL-connections with exactly
the (EC) curve requested by the client, avoiding nontransparent client/server
negotiations.

If this option is set, the default curves list built into openssl will be
ignored.
