Long: pass-file
Arg: <file>
Help: File containing the pass phrase for the private key
Protocols: SSH TLS
Category: ssh tls auth
Example: --pass-file secret.txt --key file $URL
---
Path for text file containing the passphrase for the private key.

If this option is used several times, the last one will be used.
