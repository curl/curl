Long: proxy-pass-file
Arg: <file>
Help: File containing the pass phrase for the private key for HTTPS proxy
Added: 7.79.0
Category: proxy tls auth
Example: --proxy-pass-file secret.txt --proxy-key here -x https://proxy $URL
---
Same as --pass-file but used in HTTPS proxy context.
