Long: insecure
Short: k
Help: Allow insecure server connections when using SSL
Protocols: TLS
See-also: proxy-insecure cacert
Category: tls
Example: --insecure $URL
---
By default, every SSL connection curl makes is verified to be secure. This
option allows curl to proceed and operate even for server connections
otherwise considered insecure.

The server connection is verified by making sure the server's certificate
contains the right name and verifies successfully using the cert store.

See this online resource for further details:
 https://curl.se/docs/sslcerts.html

**WARNING**: this makes the transfer insecure.
