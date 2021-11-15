Long: insecure
Short: k
Help: Allow insecure server connections when using SSL
Protocols: TLS
See-also: proxy-insecure cacert capath
Category: tls
Example: --insecure $URL
Added: 7.10
---
By default, every SSL/TLS connection curl makes is verified to be secure
before the transfer takes place. This option makes curl skip the verification
step and proceed without checking.

When this option is not used, curl verifies the server's TLS certificate
before it continues: that the certificate contains the right name which
matches the host name used in the URL and that the certificate has been signed
by a CA certificate present in the cert store.

See this online resource for further details:
 https://curl.se/docs/sslcerts.html

**WARNING**: using this option makes the transfer insecure.
