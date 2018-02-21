Long: key
Arg: <key>
Protocols: TLS SSH
Help: Private key file name
---
Private key file name. Allows you to provide your private key in this separate
file. For SSH, if not specified, curl tries the following candidates in order:
'~/.ssh/id_rsa', '~/.ssh/id_dsa', './id_rsa', './id_dsa'.

If curl is built against OpenSSL library, and the engine pkcs11 is available,
then a PKCS#11 URI (RFC 7512) can be used to specify a private key located in a
PKCS#11 device. A string beginning with "pkcs11:" will be interpreted as a
PKCS#11 URI. If a PKCS#11 URI is provided, then the --engine option will be set
as "pkcs11" if none was provided and the --key-type option will be set as
"ENG" if none was provided.

If this option is used several times, the last one will be used.
