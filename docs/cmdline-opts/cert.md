---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Short: E
Long: cert
Arg: <certificate[:password]>
Help: Client certificate file and password
Protocols: TLS
Category: tls
Added: 5.0
Multi: single
See-also:
  - cert-type
  - key
  - key-type
Example:
  - --cert certfile --key keyfile $URL
---

# `--cert`

Use the specified client certificate file when getting a file with HTTPS, FTPS
or another SSL-based protocol. The certificate must be PEM format. If the
optional password is not specified, it is queried for on the terminal. Note
that this option assumes a certificate file that is the private key and the
client certificate concatenated. See --cert and --key to specify them
independently.

In the \<certificate\> portion of the argument, you must escape the character
`:` as `\:` so that it is not recognized as the password delimiter. Similarly,
you must escape the double quote character as \" so that it is not recognized
as an escape character.

If curl is built against OpenSSL, and the engine pkcs11 or pkcs11
provider is available, then a PKCS#11 URI (RFC 7512) can be used to specify a
certificate located in a PKCS#11 device. A string beginning with `pkcs11:` is
interpreted as a PKCS#11 URI. If a PKCS#11 URI is provided, then the --engine
option is set as `pkcs11` if none was provided and the --cert-type option is
set as `ENG` or `PROV` if none was provided (depending on OpenSSL version).

If curl is built against GnuTLS, a PKCS#11 URI can be used to specify
a certificate located in a PKCS#11 device. A string beginning with `pkcs11:`
is interpreted as a PKCS#11 URI.

(Schannel) Client certificates must be specified by a path expression to a
certificate store. (Loading *PFX* is not supported; you can import it to a
store first). You can use "\<store location\>\\<store name\>\\<thumbprint\>"
to refer to a certificate in the system certificates store, for example,
*"CurrentUser\MY\934a7ac6f8a5d579285a74fa61e19f23ddfe8d7a"*. Thumbprint is
usually a SHA-1 hex string which you can see in certificate details. Following
store locations are supported: *CurrentUser*, *LocalMachine*,
*CurrentService*, *Services*, *CurrentUserGroupPolicy*,
*LocalMachineGroupPolicy* and *LocalMachineEnterprise*.
