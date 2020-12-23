Long: pubkey
Arg: <key>
Protocols: SFTP SCP
Help: SSH Public key file name
Category: sftp scp auth
---
Public key file name. Allows you to provide your public key in this separate
file.

If this option is used several times, the last one will be used.

(As of 7.39.0, curl attempts to automatically extract the public key from the
private key file, so passing this option is generally not required. Note that
this public key extraction requires libcurl to be linked against a copy of
libssh2 1.2.8 or higher that is itself linked against OpenSSL.)
