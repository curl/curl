Long: proxy-tls13-ciphers
Arg: <ciphersuite list>
help: TLS 1.3 proxy cipher suites
Protocols: TLS
---
Specifies which cipher suites to use in the connection to your HTTPS proxy
when it negotiates TLS 1.3. The list of ciphers suites must specify valid
ciphers. Read up on TLS 1.3 cipher suite details on this URL:

 https://curl.haxx.se/docs/ssl-ciphers.html

If this option is used several times, the last one will be used.
