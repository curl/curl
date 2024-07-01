---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: pinnedpubkey
Arg: <hashes>
Help: Public key to verify peer against
Protocols: TLS
Category: tls
Added: 7.39.0
Multi: single
See-also:
  - hostpubsha256
Example:
  - --pinnedpubkey keyfile $URL
  - --pinnedpubkey 'sha256//ce118b51897f4452dc' $URL
---

# `--pinnedpubkey`

Use the specified public key file (or hashes) to verify the peer. This can be
a path to a file which contains a single public key in PEM or DER format, or
any number of base64 encoded sha256 hashes preceded by 'sha256//' and
separated by ';'.

When negotiating a TLS or SSL connection, the server sends a certificate
indicating its identity. A public key is extracted from this certificate and
if it does not exactly match the public key provided to this option, curl
aborts the connection before sending or receiving any data.

This option is independent of option --insecure. If you use both options
together then the peer is still verified by public key.

PEM/DER support:

OpenSSL and GnuTLS (added in 7.39.0), wolfSSL (added in 7.43.0), mbedTLS
(added in 7.47.0), Secure Transport macOS 10.7+/iOS 10+ (added in 7.54.1),
Schannel (added in 7.58.1)

sha256 support:

OpenSSL, GnuTLS and wolfSSL (added in 7.44.0), mbedTLS (added in 7.47.0),
Secure Transport macOS 10.7+/iOS 10+ (added in 7.54.1), Schannel
(added in 7.58.1)

Other SSL backends not supported.
