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
OpenSSL 1.x used engines, whereas starting from OpenSSL 3.x providers should
be used and engines are deprecated. Also the engine tpm2tss or the
tpm2provider can be used for the private key of a client certificate. curl
provides the option --engine to load an OpenSSL engine. Providers have to be
loaded via the OpenSSL config file. See the --engine option for further
details. The following examples demonstrate how a client certificate can be
used if the private key is protected or stored in the TPM:
```bash
# OpenSSL 1.x and tpm2tss engine
# mTLS download with TSS key protected by TPM
curl --engine tpm2tss --key-type ENG --key /path/to/key.tss --cert /path/to/cert.crt https://my-server.com/download/url

# OpenSSL 3.x and tpm2 provider
# point to an OpenSSL config file that loads the default + tpm2 provider
export OPENSSL_CONF=/your/path/to/openssl.cnf
# mTLS download with TSS key protected by TPM
curl --key /path/to/key.tss --cert /path/to/cert.crt https://my-server.com/download/url
# mTLS download with key persist in the TPM
curl --key handle:0x81000000 --cert /path/to/cert.crt https://my-server.com/download/url
```

If curl is built against Secure Transport or Schannel then this option is
ignored for TLS protocols (HTTPS, etc). Those backends expect the private key
to be already present in the keychain or PKCS#12 file containing the
certificate.
