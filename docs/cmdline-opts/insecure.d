Long: insecure
Short: k
Help: Allow insecure connections when using SSL
Protocols: TLS
---
This option explicitly allows curl to perform "insecure" SSL connections and
transfers. All SSL connections are attempted to be made secure by using the CA
certificate bundle installed by default. This makes all connections considered
\&"insecure" fail unless --insecure is used.

See this online resource for further details:
 https://curl.haxx.se/docs/sslcerts.html
