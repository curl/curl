---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: key
Arg: <key>
Protocols: TLS SSH
Help: Private key filename
Category: tls ssh
Added: 7.9.3
Multi: single
See-also:
  - key-type
  - cert
Example:
  - --cert certificate --key here $URL
---

# `--key`

Private key filename. Allows you to provide your private key in this separate
file. For SSH, if not specified, curl tries the following candidates in order:
`~/.ssh/id_rsa`, `~/.ssh/id_dsa`, `./id_rsa`, `./id_dsa`.

If curl is built against OpenSSL library, and the engine pkcs11 or pkcs11
provider is available, then a PKCS#11 URI (RFC 7512) can be used to specify a
private key located in a PKCS#11 device. A string beginning with `pkcs11:` is
interpreted as a PKCS#11 URI. If a PKCS#11 URI is provided, then the --engine
option is set as `pkcs11` if none was provided and the --key-type option is
set as `ENG` or `PROV` if none was provided (depending on OpenSSL version).

If curl is built against Schannel then this option is ignored for TLS
protocols (HTTPS, etc). That backend expects the private key to be already
present in the keychain or PKCS#12 file containing the certificate.
