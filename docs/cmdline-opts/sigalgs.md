---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: sigalgs
Arg: <list>
Help: TLS signature algorithms to use
Protocols: TLS
Added: 8.14.0
Category: tls
Multi: single
See-also:
  - ciphers
Example:
  - --sigalgs ecdsa_secp256r1_sha256 $URL
---

# `--sigalgs`

Set specific signature algorithms to use during SSL session establishment according to RFC
5246, 7.4.1.4.1.

An algorithm can use either a signature algorithm and a hash algorithm pair separated by a
`+` (e.g. `ECDSA+SHA224`), or its TLS 1.3 signature scheme name (e.g. `ed25519`).

Multiple algorithms can be provided by separating them with `:`
(e.g. `DSA+SHA256:rsa_pss_pss_sha256`). The parameter is available as `-sigalgs` in the
OpenSSL `s_client` and `s_server` utilities.

`--sigalgs` allows a OpenSSL powered curl to make SSL-connections with exactly
the signature algorithms requested by the client, avoiding nontransparent client/server
negotiations.

If this option is set, the default signature algorithm list built into OpenSSL are ignored.
