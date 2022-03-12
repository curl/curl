Long: key
Arg: <key>
Protocols: TLS SSH
Help: Private key file name
Category: tls ssh
Example: --cert certificate --key here $URL
Added: 7.9.3
See-also: key-type cert
---
Private key file name. Allows you to provide your private key in this separate
file. For SSH, if not specified, curl tries the following candidates in order:
\&'~/.ssh/id_rsa', '~/.ssh/id_dsa', './id_rsa', './id_dsa'.

If curl is built against OpenSSL library, and the engine pkcs11 is available,
then a PKCS#11 URI (RFC 7512) can be used to specify a private key located in a
PKCS#11 device. A string beginning with "pkcs11:" will be interpreted as a
PKCS#11 URI. If a PKCS#11 URI is provided, then the --engine option will be set
as "pkcs11" if none was provided and the --key-type option will be set as
"ENG" if none was provided.

If curl is built against Secure Transport or Schannel then this option is
ignored for TLS protocols (HTTPS, etc). Those backends expect the private key
to be already present in the keychain or PKCS#12 file containing the
certificate.

If this option is used several times, the last one will be used.
