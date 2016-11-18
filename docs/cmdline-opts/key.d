Long: key
Arg: <key>
Protocols: TLS SSH
Help: Private key file name
---
Private key file name. Allows you to provide your private key in this separate
file. For SSH, if not specified, curl tries the following candidates in order:
'~/.ssh/id_rsa', '~/.ssh/id_dsa', './id_rsa', './id_dsa'.

If this option is used several times, the last one will be used.
